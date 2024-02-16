// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "platform.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr const auto &npos = std::string_view::npos;

using lfi_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

// TODO: https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#dos-device-paths
lfi_result lfi_impl_windows(std::string_view path, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 2;

    auto path_sep = '\\';
    if (path.find('/') != npos) {
        // Since windows filenames do not allow the forward slash character,
        // it's presence must imply that it's being used as the path separator
        path_sep = '/';
    }

    auto rpath = path;
    auto drive_end = path.find(':');
    if (drive_end != npos) {
        rpath = path.substr(drive_end + 1, path.size() - (drive_end + 1));
    }

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING || param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        if (!path.ends_with(value)) {
            continue;
        }

        if ((value[0] == path_sep && value == rpath) || (value[1] == ':' && value == path)) {
            return {{std::string(value), it.get_current_path()}};
        }

        auto parts = split(value, path_sep);
        if (parts.size() > 1 && std::find(parts.begin(), parts.end(), "..") != parts.end()) {
            return {{std::string(value), it.get_current_path()}};
        }
    }

    return {};
}

lfi_result lfi_impl_unix(std::string_view path, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 5;

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING || param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        if (value.find('/') == npos || !path.ends_with(value)) {
            continue;
        }

        if (value[0] == '/' && value == path) {
            return {{std::string(value), it.get_current_path()}};
        }

        auto parts = split(value, '/');
        if (parts.size() > 1 && std::find(parts.begin(), parts.end(), "..") != parts.end()) {
            return {{std::string(value), it.get_current_path()}};
        }
    }

    return {};
}

lfi_result lfi_impl(std::string_view path, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    if (system_platform::current() == platform::windows) {
        return lfi_impl_windows(path, params, objects_excluded, limits, deadline);
    }

    return lfi_impl_unix(path, params, objects_excluded, limits, deadline);
}
} // namespace

eval_result lfi_detector::eval_impl(const unary_argument<std::string_view> &path,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    for (const auto &param : params) {
        auto res = lfi_impl(path.value, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> path_kp{path.key_path.begin(), path.key_path.end()};
            bool ephemeral = path.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();
            cache.match =
                condition_match{{{"resource"sv, std::string{path.value}, path.address, path_kp},
                                    {"params"sv, highlight, param.address, param_kp}},
                    {std::move(highlight)}, "lfi_detector", {}, ephemeral};

            return {true, path.ephemeral || param.ephemeral};
        }
    }

    return {};
}

} // namespace ddwaf
