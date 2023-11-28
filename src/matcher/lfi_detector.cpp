// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/lfi_detector.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "transformer/normalize_path.hpp"
#include "utils.hpp"

#include <stack>

namespace ddwaf::matcher {

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
                std::string_view key{child.parameterName, child.parameterNameLength};
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
                std::string_view value{child.stringValue, child.nbEntries};
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
        std::size_t end = str.find(sep, start);

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

std::tuple<bool, std::string, std::size_t> lfi_detector::match_impl(
    const std::vector<optional_ref<const ddwaf_object>> &args)
{
    if (args.size() != 2) {
        DDWAF_DEBUG("Incorrect number of parameters provided to lfi_detector, "
                    "expected 2, obtained {}",
            args.size());
        return {};
    }

    auto path = args[0];
    auto params = args[1];

    // TODO figure out how to avoid all these checks, too clunky
    if (!path.has_value() || !params.has_value()) {
        DDWAF_DEBUG("Invalid call to lfi_detector");
        return {};
    }

    // TODO provide types on arg specification
    if (path->get().type != DDWAF_OBJ_STRING) {
        DDWAF_DEBUG("Path is not a string on lfi_detector");
        return {};
    }

    if (!object::is_container(&params->get())) {
        DDWAF_DEBUG("Params is not a container on lfi_detector");
        return {};
    }

    std::string_view path_sv{path->get().stringValue, path->get().nbEntries};

    auto [res, highlight] = lfi_impl(path_sv, params->get());

    return {res, std::move(highlight), 0};
}

} // namespace ddwaf::matcher
