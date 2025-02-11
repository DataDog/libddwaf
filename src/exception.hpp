// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <stdexcept>

namespace ddwaf {

class timeout_exception : public std::exception {
public:
    timeout_exception() : std::exception({}) {}
    timeout_exception(timeout_exception &&) = default;
    timeout_exception(const timeout_exception &) = default;
    timeout_exception &operator=(timeout_exception &&) = default;
    timeout_exception &operator=(const timeout_exception &) = default;
    ~timeout_exception() override = default;
};

class incomplete_ruleset : public std::exception {
public:
    incomplete_ruleset() : std::exception({}) {}
    incomplete_ruleset(incomplete_ruleset &&) = default;
    incomplete_ruleset(const incomplete_ruleset &) = default;
    incomplete_ruleset &operator=(incomplete_ruleset &&) = default;
    incomplete_ruleset &operator=(const incomplete_ruleset &) = default;
    ~incomplete_ruleset() override = default;
};

} // namespace ddwaf
