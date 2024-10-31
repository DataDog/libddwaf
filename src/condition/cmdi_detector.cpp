// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/cmdi_detector.hpp"
#include "condition/shi_common.hpp"
#include "condition/structured_condition.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "tokenizer/shell.hpp"
#include "transformer/common/cow_string.hpp"
#include "transformer/lowercase.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {
namespace {

enum class shell_flags {
    none,
    linux_command_opt,
    windows_command_opt,
};

// An iterator which returns the given scalar, so that the match_iterator can be
// used directly with a scalar without the need for a fully-fledged object iterator
class scalar_iterator {
public:
    explicit scalar_iterator(const ddwaf_object *obj, const std::span<const std::string> & /*path*/,
        const exclusion::object_set_ref & /*exclude*/, const object_limits & /*limits*/)
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

// Most shells support -c as a way to specify a shell command, however some
// shells such as ksh allow for the first argument to be a shell command
std::unordered_map<std::string_view, std::string_view> known_shells{
    {"sh", "c"},
    {"bash", "c"},
    {"ksh", {}},
    {"rksh", {}},
    {"fish", "c"},
    {"zsh", "c"},
    {"dash", "c"},
    {"ash", "c"},
    {"powershell", "Command"},
    {"powershell.exe", "Command"},
};

std::string_view basename(std::string_view path)
{
    auto idx = path.find_last_of(R"(\/)"sv);
    return idx == std::string_view::npos ? std::string_view{} : path.substr(idx + 1);
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

std::string str_lowercase(std::string_view str)
{
    auto buffer = std::string{str};

    // By initialising the cow_string with the underlying data
    // contained within the std::string, we ensure a new one won't be
    // allocated once the string is modified.
    cow_string str_lc{buffer.data(), buffer.size()};
    transformer::lowercase::transform(str_lc);

    str_lc.move(); // move to avoid freeing the string

    return buffer; // NOLINT(clang-analyzer-unix.Malloc)
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

std::string_view find_shell_command(std::string_view executable, const ddwaf_object &exec_args)
{
    auto executable_lc = str_lowercase(executable);
    auto shell_it = known_shells.find(basename(executable_lc));
    if (shell_it != known_shells.end()) {
        // We've found that the current exec command is attempting to run a
        // a shell. The shell binary itself might be injected, but also the
        // shell command. So we need to identify the command
        std::size_t i = 1;
        if (!shell_it->second.empty()) {
            // Most shells allow specifying a command with -c
            for (; i < object_size(exec_args); ++i) {
                auto opt = trim_whitespaces(object_at(exec_args, i));
                if (!opt.empty() && opt[0] == '-' &&
                    opt.find(shell_it->second) != std::string_view::npos) {
                    // We've found the -c option, we can now break, if it isn't found
                    // i will reach the end of the array
                    break;
                }
            }
        }
        for (; i < object_size(exec_args); ++i) {
            auto arg = trim_whitespaces(object_at(exec_args, i));

            if (!arg.empty() && arg[0] == '-') {
                continue;
            }

            // Once the first non-option argument is reached, it must be the
            // shell command
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
    auto shell_command = find_shell_command(executable, exec_args);

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
        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        value = trim_whitespaces(value);
        if (executable == value) {
            // When the full binary has been injected, we consider it an exploit
            // although bear in mind that this can also be a vulnerable-by-design
            // application, leading to a false positive
            return {{std::string(value), it.get_current_path()}};
        }

        if (!shell_command.empty()) {
            auto res = find_shi_from_params<std::string_view, scalar_iterator>(
                shell_command, resource_tokens, param, objects_excluded, limits, deadline);
            if (res.has_value()) {
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
        if (!resource.empty()) {
            resource.append(" "sv);
        }
        resource.append(child);
    }
    return resource;
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

    std::vector<shell_token> resource_tokens;
    for (const auto &param : params) {
        auto res = cmdi_impl(
            *resource.value, resource_tokens, *param.value, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> resource_kp{
                resource.key_path.begin(), resource.key_path.end()};
            const bool ephemeral = resource.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{{{"resource"sv, generate_string_resource(*resource.value),
                                               resource.address, resource_kp},
                                              {"params"sv, highlight, param.address, param_kp}},
                {std::move(highlight)}, "cmdi_detector"sv, {}, ephemeral};

            return {true, ephemeral};
        }
    }

    return {};
}
} // namespace ddwaf
