// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>

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

} // namespace

obfuscator::obfuscator(std::string_view key_regex_str, std::string_view value_regex_str)
{
    re2::RE2::Options options;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    options.set_max_mem(static_cast<int64_t>(512 * 1024));
    options.set_log_errors(false);
    options.set_case_sensitive(false);

    if (!key_regex_str.empty()) {
        re2::StringPiece sp(key_regex_str.data(), key_regex_str.size());
        key_regex = std::make_unique<re2::RE2>(sp, options);

        if (!key_regex->ok()) {
            DDWAF_ERROR("invalid obfuscator key regex: {} - using default", key_regex->error_arg());

            sp = re2::StringPiece(default_key_regex_str.data(), default_key_regex_str.size());
            key_regex = std::make_unique<re2::RE2>(sp, options);

            if (!key_regex->ok()) {
                throw std::runtime_error(
                    "invalid default obfuscator key regex: " + key_regex->error_arg());
            }
        }
    }

    if (!value_regex_str.empty()) {
        const re2::StringPiece sp(value_regex_str.data(), value_regex_str.size());
        value_regex = std::make_unique<re2::RE2>(sp, options);

        if (!value_regex->ok()) {
            DDWAF_ERROR("invalid obfuscator value regex: {}", value_regex->error_arg());
        }
    }
}

bool obfuscator::is_sensitive_key(std::string_view key) const
{
    return key_regex ? match(*key_regex, key) : false;
}

bool obfuscator::is_sensitive_value(std::string_view value) const
{
    return value_regex ? match(*value_regex, value) : false;
}

} // namespace ddwaf
