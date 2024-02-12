// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <stack>

#include "condition/lfi_detector.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr std::size_t min_str_len = 5;

std::vector<std::string_view> match_params(std::string_view path, const ddwaf_object &params)
{
    std::stack<const ddwaf_object *> stack;
    std::vector<std::string_view> strings;

    stack.push(&params);

    while (!stack.empty() && stack.size() <= object_limits::default_max_container_depth) {
        const ddwaf_object &container = *stack.top();
        stack.pop();

        for (std::size_t i = 0; i < container.nbEntries; ++i) {
            const ddwaf_object &child = container.array[i];

            if (child.parameterName != nullptr && child.parameterNameLength >= min_str_len) {
                const std::string_view key{
                    child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};
                if (path.find(key) != std::string_view::npos) {
                    strings.emplace_back(key);
                }
            }

            if (object::is_container(&child)) {
                if (stack.size() < object_limits::default_max_container_depth) {
                    stack.push(&child);
                }
                continue;
            }

            if (child.type == DDWAF_OBJ_STRING && child.nbEntries >= min_str_len) {
                const std::string_view value{
                    child.stringValue, static_cast<std::size_t>(child.nbEntries)};
                if (path.find(value) != std::string_view::npos) {
                    strings.emplace_back(value);
                }
            }
        }
    }

    return strings;
}

std::vector<std::string_view> split(std::string_view str, char sep)
{
    std::vector<std::string_view> components;

    std::size_t start = 0;
    while (start < str.size()) {
        const std::size_t end = str.find(sep, start);

        if (end == start) {
            // Ignore zero-sized strings
            start = end + 1;
        }

        if (end == std::string_view::npos) {
            // Last element
            components.emplace_back(str.substr(start));
            start = str.size();
        } else {
            components.emplace_back(str.substr(start, end - start));
            start = end + 1;
        }
    }

    return components;
}

std::pair<bool, std::string> lfi_impl(std::string_view path, const ddwaf_object &params)
{
    auto matched_params = match_params(path, params);
    if (matched_params.empty()) {
        return {};
    }

    for (const auto &param : matched_params) {
        if (param[0] == '/' && param == path) {
            return {true, std::string(param)};
        }

        if (!path.ends_with(param)) {
            continue;
        }

        auto parts = split(param, '/');
        if (parts.size() > 1 && std::find(parts.begin(), parts.end(), "..") != parts.end()) {
            return {true, std::string(param)};
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
