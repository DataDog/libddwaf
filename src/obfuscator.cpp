// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <obfuscator.hpp>
#include <utils.h>

namespace ddwaf
{

namespace
{

bool match(re2::RE2 &regex, std::string_view value)
{
    size_t length = findStringCutoff(value.data(), value.size());
    const re2::StringPiece key_ref(value.data(), length);

    return regex.Match(key_ref, 0, length, re2::RE2::UNANCHORED, nullptr, 0);
}

}

obfuscator::obfuscator(std::string_view key_regex_str,
    std::string_view value_regex_str)
{
    re2::RE2::Options options;
    options.set_max_mem(512 * 1024);
    options.set_log_errors(false);
    options.set_case_sensitive(false);

    if (!key_regex_str.empty()) {
        key_regex = std::make_unique<re2::RE2>(key_regex_str, options);
    }

    if (!value_regex_str.empty()) {
        value_regex = std::make_unique<re2::RE2>(value_regex_str, options);
    }
}

bool obfuscator::obfuscate_key(std::string_view key) const
{
    if (key_regex && match(*key_regex, key)) {
        return true;
    }

    return false;
}


bool obfuscator::obfuscate_value(std::string_view value) const
{
    if (value_regex && match(*value_regex, value)) {
        return true;
    }

    return false;
}

}
