// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <re2/re2.h>
#include <string_view>
#include <memory>
#include <ddwaf.h>

namespace ddwaf
{

// For now this class only services as an inmutable instance of an obfuscator
// which provides a verdict regarding whether to obfuscate or not. Eventually
// the objective would be to directly pass events to the obfuscator and have it
// obfuscate as required.

class obfuscator
{
public:
    explicit obfuscator(std::string_view key_regex_str = std::string_view(),
        std::string_view value_regex_str = std::string_view());
    bool obfuscate_key(std::string_view key) const;
    bool obfuscate_value(std::string_view value) const;

protected:
    std::unique_ptr<re2::RE2> key_regex { nullptr };
    std::unique_ptr<re2::RE2> value_regex { nullptr };
};

}
