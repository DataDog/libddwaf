// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <iostream>
#include <stack>

#include "condition/lfi_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr std::size_t min_str_len = 5;

std::pair<bool, std::string> lfi_impl(std::string_view path, const ddwaf_object &params)
{
    object::kv_iterator it(&params, {}, {});
    for (; it; ++it) {
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
            return {true, std::string(value)};
        }

        if (!path.ends_with(value)) {
            continue;
        }

        auto parts = split(value, '/');
        // for (auto p : parts) { std::cout << p << std::endl; }
        if (parts.size() > 1 && std::find(parts.begin(), parts.end(), "..") != parts.end()) {
            return {true, std::string(value)};
        }
    }

    return {};
}

} // namespace

eval_result lfi_detector::eval_impl(const unary_argument<std::string_view> &path,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    ddwaf::timer &deadline) const
{
    for (const auto &param : params) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        auto [res, highlight] = lfi_impl(path.value, *param.value);

        if (res) {
            std::vector<std::string> param_kp{param.key_path.begin(), param.key_path.end()};
            std::vector<std::string> path_kp{path.key_path.begin(), path.key_path.end()};
            bool ephemeral = path.ephemeral || param.ephemeral;

            cache.match =
                condition_match{{{"resource"sv, std::string{path.value}, path.address, path_kp},
                                    {"params"sv, highlight, param.address, param_kp}},
                    {std::move(highlight)}, "lfi_detector", {}, ephemeral};

            return {res, path.ephemeral || param.ephemeral};
        }
    }

    return {};
}

} // namespace ddwaf
