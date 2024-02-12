// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/lfi_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr std::size_t min_str_len = 5;

using lfi_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

lfi_result lfi_impl(std::string_view path, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING || param.stringValue == nullptr ||
            param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        if (path.find(value) == std::string_view::npos) {
            continue;
        }

        if (value[0] == '/' && value == path) {
            return {{std::string(value), it.get_current_path()}};
        }

        if (!path.ends_with(value)) {
            continue;
        }

        auto parts = split(value, '/');
        if (parts.size() > 1 && std::find(parts.begin(), parts.end(), "..") != parts.end()) {
            return {{std::string(value), it.get_current_path()}};
        }
    }

    return {};
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
