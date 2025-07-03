// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/cmdi_detector.hpp"
#include "condition/shi_common.hpp"
#include "condition/structured_condition.hpp"
#include "cow_string.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "platform.hpp"
#include "tokenizer/shell.hpp"
#include "transformer/lowercase.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {
namespace {

// An iterator which returns the given scalar, so that the match_iterator can be
// used directly with a scalar without the need for a fully-fledged object iterator
class scalar_iterator {
public:
    explicit scalar_iterator(const ddwaf_object *obj, const std::span<const std::string> & /*path*/,
        const exclusion::object_set_ref & /*exclude*/, const object_limits & /*limits*/
        )
        : current_(obj)
    {}

    ~scalar_iterator() = default;

    scalar_iterator(const scalar_iterator &) = default;
    scalar_iterator(scalar_iterator &&) noexcept = default;

    scalar_iterator &operator=(const scalar_iterator &) = delete;
    scalar_iterator &operator=(scalar_iterator &&) noexcept = delete;

    [[nodiscard]] const ddwaf_object *operator*() { return current_; }
    bool operator++()
    {
        current_ = nullptr;
        return false;
    }
    [[nodiscard]] explicit operator bool() const { return current_ != nullptr; }
    [[nodiscard]] static std::vector<std::string> get_current_path() { return {}; }

protected:
    const ddwaf_object *current_;
};

struct opt_spec {
    // If set to true, an option will be used to indicate the presence of a
    // shell command, for example -c or -Command, otherwise the first non-option
    // argument is used
    bool requires_command_opt{false};
    // If set to true, the shell command will be immediately present after the
    // command option. Note that this can only be true if requires_command_opt
    // is also true.
    bool command_after_opt{false};
    // Indicates the platform type of the shell, this determines how options
    // are interpreted from the command line.
    platform shell_platform;
    // The possible options hich can be used to indicate that a command is
    // present in the call
    std::unordered_set<std::string_view> command_opt;
    // The options which require and argument
    std::unordered_set<std::string_view> opts_with_arg;
};

// Most shells support -c as a way to specify a shell command, however some
// shells such as ksh allow for the first argument to be a shell command
std::unordered_map<std::string_view, opt_spec> known_shells{
    // sh could be bash (red-hat) or dash (debian) so we cast a wide net
    {"sh", {.requires_command_opt = true,
               .command_after_opt = false,
               .shell_platform = platform::linux,
               .command_opt = {"c"},
               .opts_with_arg = {"O", "o", "init-file", "rcfile"}}},
    {"bash", {.requires_command_opt = true,
                 .command_after_opt = false,
                 .shell_platform = platform::linux,
                 .command_opt = {"c"},
                 .opts_with_arg = {"O", "o", "init-file", "rcfile"}}},
    {"ksh", {.requires_command_opt = false,
                .command_after_opt = false,
                .shell_platform = platform::linux,
                .command_opt = {"c"},
                .opts_with_arg = {"o", "T"}}},
    {"rksh", {.requires_command_opt = false,
                 .command_after_opt = false,
                 .shell_platform = platform::linux,
                 .command_opt = {"c"},
                 .opts_with_arg = {"o", "T"}}},
    {"fish", {.requires_command_opt = true,
                 .command_after_opt = true,
                 .shell_platform = platform::linux,
                 .command_opt = {"c", "command"},
                 .opts_with_arg = {}}},
    {"zsh", {.requires_command_opt = true,
                .command_after_opt = false,
                .shell_platform = platform::linux,
                .command_opt = {"c"},
                .opts_with_arg = {"o"}}},
    {"dash", {.requires_command_opt = true,
                 .command_after_opt = false,
                 .shell_platform = platform::linux,
                 .command_opt = {"c"},
                 .opts_with_arg = {"o"}}},
    {"ash", {.requires_command_opt = true,
                .command_after_opt = false,
                .shell_platform = platform::linux,
                .command_opt = {"c"},
                .opts_with_arg = {"o"}}},
    {"powershell", {.requires_command_opt = true,
                       .command_after_opt = true,
                       .shell_platform = platform::windows,
                       .command_opt = {"command", "commandwithargs"},
                       .opts_with_arg = {}}},
    {"pwsh", {.requires_command_opt = true,
                 .command_after_opt = true,
                 .shell_platform = platform::windows,
                 .command_opt = {"command", "commandwithargs"},
                 .opts_with_arg = {}}},
};

std::string_view basename(std::string_view path)
{
    std::size_t idx = std::string_view::npos;
    if (system_platform::is(platform::windows)) {
        idx = path.find_last_of(R"(\/)"sv);
    } else {
        idx = path.find_last_of('/');
    }
    return idx == std::string_view::npos ? path : path.substr(idx + 1);
}

std::string_view trim_quotes(std::string_view str)
{
    if (str.size() > 1 && ((str.front() == '"' && str.back() == '"') ||
                              (str.front() == '\'' && str.back() == '\''))) {
        str.remove_prefix(1);
        str.remove_suffix(1);
    }

    return str;
}

std::string_view trim_whitespaces(std::string_view str)
{
    static const std::string_view whitespaces = " \f\n\r\t\v";

    if (str.empty()) {
        return {};
    }

    auto start = str.find_first_not_of(whitespaces);
    if (start == std::string_view::npos) {
        return {};
    }

    auto end = str.find_last_not_of(whitespaces);
    return str.substr(start, 1 + end - start);
}

std::size_t object_size(const ddwaf_object &obj) { return static_cast<std::size_t>(obj.nbEntries); }

std::string_view object_at(const ddwaf_object &obj, std::size_t idx)
{
    const ddwaf_object &child = obj.array[idx];
    if (child.type != DDWAF_OBJ_STRING) {
        return {};
    }
    return {child.stringValue, object_size(child)};
}

enum class opt_type : uint8_t { none, short_opt, long_opt, end_opt };

inline std::pair<std::string_view, std::string_view> split_long_opt_with_arg(std::string_view opt)
{
    // We need at least three characters, e.g.: x=y
    if (opt.size() < 3) {
        return {opt, {}};
    }

    // Check if the opt has =
    auto idx = opt.find('=');
    // if the idx is found at the beginning or the end, bail
    if (idx == std::string_view::npos || idx == 0 || idx == opt.size() - 1) {
        return {opt, {}};
    }

    return {opt.substr(0, idx), trim_quotes(opt.substr(idx + 1, opt.size() - (idx + 1)))};
}

// arg must not be empty
inline std::tuple<std::string_view, std::string_view, opt_type> parse_option(
    const opt_spec &spec, std::string_view arg)
{
    if (spec.shell_platform == platform::windows && (arg[0] == '-' || arg[0] == '/')) {
        arg.remove_prefix(1);
        if (arg.starts_with('-')) {
            // Powershell in linux allows --
            arg.remove_prefix(1);
        }

        return {arg, {}, opt_type::long_opt};
    }

    if (spec.shell_platform == platform::linux) {
        if (arg[0] == '-') {
            arg.remove_prefix(1);
            if (arg.starts_with('-')) {
                arg.remove_prefix(1);
                if (arg.empty()) {
                    return {{}, {}, opt_type::end_opt};
                }

                // The long option might have the format x=y
                auto [key, value] = split_long_opt_with_arg(arg);
                return {key, value, opt_type::long_opt};
            }
            return {arg, {}, opt_type::short_opt};
        }

        if (arg[0] == '+') {
            arg.remove_prefix(1);
            return {arg, {}, opt_type::short_opt};
        }
    }

    return {{}, {}, opt_type::none};
}

std::string_view find_shell_command(std::string_view executable, const ddwaf_object &exec_args)
{
    // By initialising the cow_string with the underlying data
    // contained within the std::string, we ensure a new one won't be
    // allocated once the string is modified.
    cow_string executable_lc{executable};

    // Lowercase the executable in windows due to being case insensitivity
    if (system_platform::is(platform::windows)) {
        if (transformer::lowercase::transform(executable_lc)) {
            executable = static_cast<std::string_view>(executable_lc);
        }

        if (executable.ends_with(".exe")) {
            executable.remove_suffix(4);
        }
    }

    auto shell_it = known_shells.find(basename(executable));
    if (shell_it == known_shells.end()) {
        return {};
    }

    // We've found that the current exec command is attempting to run a
    // a shell. The shell binary itself might be injected, but also the
    // shell command. So we need to identify the command
    auto &spec = shell_it->second;

    bool command_opt_found = !spec.requires_command_opt;
    for (std::size_t i = 1; i < object_size(exec_args); ++i) {
        auto arg = object_at(exec_args, i);
        if (arg.empty()) {
            continue;
        }

        auto [opt, embedded_arg, type] = parse_option(spec, arg);
        // For every short_opt, we need to check if it requires an argument
        if (type == opt_type::short_opt) {
            for (std::size_t j = 0; j < opt.size(); ++j) {
                const auto single_opt = opt.substr(j, 1);
                // If we're looking for a command opt...
                command_opt_found = command_opt_found || spec.command_opt.contains(single_opt);

                // If the shell requires the command immediately after the opt, we
                // simply return the next argument
                if (spec.command_after_opt && command_opt_found) {
                    if (i + 1 >= object_size(exec_args)) {
                        return {};
                    }

                    return object_at(exec_args, i + 1);
                }

                // Check if the option requires an argument
                if (spec.opts_with_arg.contains(single_opt)) {
                    // Skip the next argument
                    ++i;
                }
            }
        } else if (type == opt_type::long_opt) {
            cow_string opt_lc{opt};
            if (spec.shell_platform == platform::windows &&
                transformer::lowercase::transform(opt_lc)) {
                // powershell accepts long options without considering case
                opt = static_cast<std::string_view>(opt_lc);
            }

            // If we're looking for a command opt...
            command_opt_found = command_opt_found || spec.command_opt.contains(opt);

            // If the shell requires the command immediately after the opt, we
            // simply return the next argument
            if (spec.command_after_opt && command_opt_found) {
                if (embedded_arg.empty() && i + 1 >= object_size(exec_args)) {
                    break;
                }

                return embedded_arg.empty() ? object_at(exec_args, i + 1) : embedded_arg;
            }

            // Check if the option requires an argument
            if (spec.opts_with_arg.contains(opt)) {
                // Skip the next argument
                ++i;
            }
        } else if (type == opt_type::end_opt) {
            // Since we found the end of options, the next argument must be
            // the shell invocation, but only if we have found the relevant
            // command option (assuming it's required)
            if (!command_opt_found || i + 1 >= object_size(exec_args)) {
                break;
            }

            return object_at(exec_args, i + 1);
        } else {
            // Once the first non-option argument is reached, it must be the
            // shell command, unless the command opt is required and hasn't
            // been found
            if (!command_opt_found) {
                break;
            }

            return arg;
        }
    }

    return {};
}

std::optional<shi_result> cmdi_impl(const ddwaf_object &exec_args,
    std::vector<shell_token> &resource_tokens, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    const std::string_view executable = trim_whitespaces(object_at(exec_args, 0));
    if (executable.empty()) {
        return {};
    }

    // Restrict the executable matches to those with more than one component,
    // or rather those not in the PATH
    const auto exec_basename = basename(executable);
    const bool eval_executable = (exec_basename != executable);

    // Find any associated shell command, if the current executable is a shell
    auto shell_command = find_shell_command(exec_basename, exec_args);

    if (shell_command.empty() && !eval_executable) {
        // No shell command and we're not evaluating the executable, bail
        return std::nullopt;
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

        if (eval_executable) {
            // First check if the entire executable was injected
            std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
            value = trim_whitespaces(value);
            if (executable == value) {
                // When the full binary has been injected, we consider it an exploit
                // although bear in mind that this can also be a vulnerable-by-design
                // application, leading to a false positive
                return {{.value = std::string(value), .key_path = it.get_current_path()}};
            }
        }

        if (!shell_command.empty()) {
            auto res = find_shi_from_params<std::string_view, scalar_iterator>(
                shell_command, resource_tokens, param, objects_excluded, limits, deadline);
            if (res.has_value()) {
                res->key_path = it.get_current_path();
                return res;
            }
        }
    }

    return std::nullopt;
}

std::string generate_string_resource(const ddwaf_object &root)
{
    std::string resource;
    for (std::size_t i = 0; i < object_size(root); ++i) {
        auto child = object_at(root, i);
        if (i > 0) {
            resource.append(R"( ")");
            resource.append(child);
            resource.append(R"(")");
        } else {
            resource.append(child);
        }
    }
    return resource;
}

} // namespace

cmdi_detector::cmdi_detector(std::vector<condition_parameter> args)
    : base_impl<cmdi_detector>(std::move(args))
{}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
eval_result cmdi_detector::eval_impl(const unary_argument<const ddwaf_object *> &resource,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline) const
{
    if (resource.value->type != DDWAF_OBJ_ARRAY || resource.value->nbEntries == 0) {
        return {};
    }

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res = cmdi_impl(
            *resource.value, resource_tokens, *param.value, objects_excluded, limits, deadline);
        if (res.has_value()) {
            const std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match =
                condition_match{.args = {{.name = "resource"sv,
                                             .resolved = generate_string_resource(*resource.value),
                                             .address = resource.address,
                                             .key_path = resource_kp},
                                    {.name = "params"sv,
                                        .resolved = highlight,
                                        .address = param.address,
                                        .key_path = param_kp}},
                    .highlights = {std::move(highlight)},
                    .operator_name = "cmdi_detector"sv,
                    .operator_value = {},
                    .ephemeral = ephemeral};

            return {.outcome = true, .ephemeral = ephemeral};
        }
    }

    return {};
}
} // namespace ddwaf
