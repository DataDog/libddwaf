// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

#include "condition/base.hpp"
#include "dynamic_string.hpp"
#include "log.hpp"
#include "obfuscator.hpp"
#include "re2.h"
#include "stringpiece.h"

namespace ddwaf {

namespace {

bool match(re2::RE2 &regex, std::string_view value)
{
    const re2::StringPiece key_ref(value.data(), value.size());
    return regex.Match(key_ref, 0, value.size(), re2::RE2::UNANCHORED, nullptr, 0);
}

bool load_regex(std::string_view regex_str, std::unique_ptr<re2::RE2> &regex)
{
    if (regex_str.empty()) {
        return true;
    }

    re2::RE2::Options options;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    options.set_max_mem(static_cast<int64_t>(512 * 1024));
    options.set_log_errors(false);
    options.set_case_sensitive(false);

    const re2::StringPiece sp(regex_str.data(), regex_str.size());
    regex = std::make_unique<re2::RE2>(sp, options);

    return regex->ok();
}

template <std::size_t N, std::size_t... I>
bool find_and_consume_sequence(re2::StringPiece *input, re2::RE2 &regex,
    std::array<re2::StringPiece, N> &array, std::index_sequence<I...> /*unused*/)
{
    return re2::RE2::FindAndConsume(input, regex, &array[I]...);
}

template <std::size_t N>
bool find_and_consume(
    re2::StringPiece *input, re2::RE2 &regex, std::array<re2::StringPiece, N> &array)
{
    return find_and_consume_sequence(input, regex, array, std::make_index_sequence<N>{});
}

} // namespace

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
obfuscator::obfuscator(std::string_view key_regex_str, std::string_view value_regex_str)
{
    if (!load_regex(key_regex_str, key_regex_)) {
        DDWAF_ERROR("invalid obfuscator key regex: {} - using default", key_regex_->error_arg());

        // Assume the default regex won't fail, this will be validated during testing
        load_regex(default_key_regex_str, key_regex_);
    }

    bool value_regex_is_default = (value_regex_str == default_value_regex_str);
    if (!load_regex(value_regex_str, value_regex_)) {
        DDWAF_ERROR(
            "invalid obfuscator value regex: {} - using default", value_regex_->error_arg());

        // Assume the default regex won't fail, this will be validated during testing
        load_regex(default_value_regex_str, value_regex_);
        value_regex_is_default = true;
    }

    if (value_regex_ && value_regex_->ok()) {
        partial_value_obfuscation_ = value_regex_is_default;
    }
}

void obfuscator::obfuscate_match(condition_match &match) const
{
    bool redact_highlight = false;
    for (auto &arg : match.args) {
        bool sensitive_key = false;
        for (const auto &key : arg.key_path) {
            if (is_sensitive_key(key)) {
                sensitive_key = true;
                break;
            }
        }

        if (sensitive_key) {
            // The key is sensitive, we must replace the resolved value and highlight
            redact_highlight = (arg.name == "params" || arg.name == "input");

            arg.resolved = redaction_msg;
        } else {
            if (obfuscate_value(arg.resolved)) {
                redact_highlight = (arg.name == "params" || arg.name == "input");
            }
        }
    }

    // Since the highlight may be partial, there's no guarantee that the
    // regular expressions will correctly match, therefore we fully redact
    // them
    if (redact_highlight) {
        for (auto &highlight : match.highlights) { highlight = redaction_msg; }
    }
}

bool obfuscator::is_sensitive_key(std::string_view key) const
{
    return (key_regex_ && key_regex_->ok()) ? match(*key_regex_, key) : false;
}

bool obfuscator::is_sensitive_value(std::string_view value) const
{
    return (value_regex_ && value_regex_->ok()) ? match(*value_regex_, value) : false;
}

bool obfuscator::obfuscate_value(dynamic_string &value) const
{
    if (!partial_value_obfuscation_) {
        if (is_sensitive_value(value)) {
            value = redaction_msg;
            return true;
        }
        return false;
    }

    dynamic_string output{value.size()};
    re2::StringPiece input{value.data(), value.size()};

    auto prev = input;
    while (!input.empty()) {
        std::array<re2::StringPiece, 8> matches;
        if (find_and_consume(&input, *value_regex_, matches)) {
            for (auto &match : matches) {
                if (!match.empty()) {
                    output.append({prev.data(), match.data() - prev.data()});
                    output.append(redaction_msg);

                    const auto *next = match.data() + match.size();
                    if (next != input.data()) {
                        output.append({next, input.data() - next});
                    }
                    break;
                }
            }
            prev = input;
        }
    }

    if (!output.empty()) {
        output.append({prev.data(), prev.size()});
        value = output;
    }

    return !output.empty();
}

} // namespace ddwaf
