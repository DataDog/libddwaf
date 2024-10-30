// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/cmdi_detector.hpp"
#include "condition/match_iterator.hpp"
#include "condition/shi_common.hpp"
#include "condition/structured_condition.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "log.hpp"
#include "tokenizer/shell.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {
namespace {

// Most shells support -c as a way to specify a shell command, however some
// shells such as ksh allow for the first argument to be a shell command
std::unordered_set<std::string_view> known_shells{
    "sh", "bash", "ksh", "rksh", "fish", "zsh", "dash", "ash"};

std::string_view basename(std::string_view path)
{
    auto idx = path.find_last_of(R"(\/)"sv);
    return idx == std::string_view::npos ? std::string_view{} : path.substr(idx + 1);
}

std::string_view trim_whitespaces(std::string_view str)
{
    std::size_t i = 0;
    for (; i < str.size() && isspace(str[i]); ++i) {}
    return i < str.size() ? str.substr(i) : std::string_view{};
}

std::optional<shi_result> cmdi_impl(const std::vector<std::string_view> &exec_args,
    std::vector<shell_token> &resource_tokens, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    // TODO: support indirect executable injection, e.g. time <command>

    std::string_view executable = exec_args[0];
    std::string_view shell_command;

    auto binary_path = basename(executable);
    if (known_shells.contains(binary_path)) {
        // We've found that the current exec command is attempting to run a
        // a shell. The shell binary itself might be injected, but also the
        // shell command. So we need to identify the command
        // Most shells allow specifying a command with -c
        for (std::size_t i = 1; i < exec_args.size(); ++i) {
            auto arg = trim_whitespaces(exec_args[i]);
            if (arg[0] == '-' && arg.find('c') == std::string_view::npos &&
                i + 1 < exec_args.size()) {
                shell_command = exec_args[i + 1];
                break;
            }
        }
        // TODO ksh and rksh don't require -c
    }

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING) {
            continue;
        }

        // First check if the entire executable was injected
        const std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        if (executable == value) {
            // When the full binary has been injected, we consider it an exploit
            // although bear in mind that this can also be a vulnerable-by-design
            // application, leading to a false positive
            return {{std::string(value), it.get_current_path()}};
        }
    }

    return {};

    return std::nullopt;
}

} // namespace

cmdi_detector::cmdi_detector(std::vector<condition_parameter> args, const object_limits &limits)
    : base_impl<cmdi_detector>(std::move(args), limits)
{}

eval_result cmdi_detector::eval_impl(const unary_argument<const ddwaf_object *> &resource,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    if (resource.value->type != DDWAF_OBJ_ARRAY || resource.value->nbEntries == 0) {
        return {};
    }

    std::vector<std::string> exec_args;
    exec_args.reserve(resource.value->nbEntries);
    for (std::size_t i = 0; i < resource.value->nbEntries; ++i) {
        auto &value = resource.value->array[i];
        if (value.type != DDWAF_OBJ_STRING) {
            continue;
        }
        exec_args.emplace_back(value.stringValue, static_cast<std::size_t>(value.nbEntries));
    }

    std::string resource_sv;
    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res = shi_impl(
            resource_sv, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{
                {{"resource"sv, std::string{resource_sv}, resource.address, resource_kp},
                    {"params"sv, highlight, param.address, param_kp}},
                {std::move(highlight)}, "cmdi_detector"sv, {}, ephemeral};

            return {true, ephemeral};
        }
    }

    return {};
}
} // namespace ddwaf
