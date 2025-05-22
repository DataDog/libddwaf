// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <re2/re2.h>
#include <string_view>

#include "condition/base.hpp"

namespace ddwaf {

// For now this class only services as an inmutable instance of an obfuscator
// which provides a verdict regarding whether to obfuscate or not. Eventually
// the objective would be to directly pass events to the obfuscator and have it
// obfuscate as required.

class match_obfuscator {
public:
    explicit match_obfuscator(std::string_view key_regex_str = std::string_view(),
        std::string_view value_regex_str = std::string_view());

    void obfuscate_match(condition_match &match) const;

    [[nodiscard]] bool is_sensitive_key(std::string_view key) const;
    [[nodiscard]] bool is_sensitive_value(std::string_view value) const;

    static constexpr std::string_view redaction_msg{"<Redacted>"};

    static constexpr std::string_view default_key_regex_str{
        R"((?i)pass|pw(?:or)?d|secret|(?:api|private|public|access)[_-]?key|token|consumer[_-]?(?:id|key|secret)|sign(?:ed|ature)|bearer|authorization|jsessionid|phpsessid|asp\.net[_-]sessionid|sid|jwt)"};

    static constexpr std::string_view default_value_regex_str{
        R"((?i)(?:p(?:ass)?w(?:or)?d|pass(?:[_-]?phrase)?|secret(?:[_-]?key)?|(?:(?:api|private|public|access)[_-]?)key(?:[_-]?id)?|(?:(?:auth|access|id|refresh)[_-]?)?token|consumer[_-]?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?|jsessionid|phpsessid|asp\.net(?:[_-]|-)sessionid|sid|jwt)(?:\s*=([^;&]+)|"\s*:\s*("[^"]+"|\d+))|bearer\s+([a-z0-9\._\-]+)|token\s*:\s*([a-z0-9]{13})|gh[opsu]_([0-9a-zA-Z]{36})|ey[I-L][\w=-]+\.(ey[I-L][\w=-]+(?:\.[\w.+\/=-]+)?)|[\-]{5}BEGIN[a-z\s]+PRIVATE\sKEY[\-]{5}([^\-]+)[\-]{5}END[a-z\s]+PRIVATE\sKEY|ssh-rsa\s*([a-z0-9\/\.+]{100,}))"};

protected:
    [[nodiscard]] bool obfuscate_value(dynamic_string &value) const;

    bool partial_value_obfuscation_{false};
    std::unique_ptr<re2::RE2> key_regex_{nullptr};
    std::unique_ptr<re2::RE2> value_regex_{nullptr};
};

} // namespace ddwaf
