// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <stdexcept>
#include <string>
#include <utility>

#include "fmt/format.h"

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

enum class parser_error_severity : uint8_t { warning, error };

class parsing_exception : public std::exception {
public:
    ~parsing_exception() override = default;

    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }
    [[nodiscard]] parser_error_severity severity() const noexcept { return sev_; }

protected:
    explicit parsing_exception(parser_error_severity sev, std::string what = {})
        : sev_(sev), what_(std::move(what))
    {}
    parsing_exception(parsing_exception &&) = default;
    parsing_exception(const parsing_exception &) = default;
    parsing_exception &operator=(parsing_exception &&) = default;
    parsing_exception &operator=(const parsing_exception &) = default;

    parser_error_severity sev_;
    std::string what_;
};

class parsing_error : public parsing_exception {
public:
    explicit parsing_error(std::string what = {})
        : parsing_exception(parser_error_severity::error, std::move(what))
    {}
    parsing_error(parsing_error &&) = default;
    parsing_error(const parsing_error &) = default;
    parsing_error &operator=(parsing_error &&) = default;
    parsing_error &operator=(const parsing_error &) = default;
    ~parsing_error() override = default;
};

class parsing_warning : public parsing_exception {
public:
    explicit parsing_warning(std::string what = {})
        : parsing_exception(parser_error_severity::warning, std::move(what))
    {}
    parsing_warning(parsing_warning &&) = default;
    parsing_warning(const parsing_warning &) = default;
    parsing_warning &operator=(parsing_warning &&) = default;
    parsing_warning &operator=(const parsing_warning &) = default;
    ~parsing_warning() override = default;
};

class unsupported_schema_version : public parsing_warning {
public:
    unsupported_schema_version() = default;
    unsupported_schema_version(unsupported_schema_version &&) = default;
    unsupported_schema_version(const unsupported_schema_version &) = default;
    unsupported_schema_version &operator=(unsupported_schema_version &&) = default;
    unsupported_schema_version &operator=(const unsupported_schema_version &) = default;
    ~unsupported_schema_version() override = default;
};

class unsupported_operator_version : public parsing_warning {
public:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    unsupported_operator_version(std::string_view name, unsigned expected, unsigned current)
        : parsing_warning(ddwaf::fmt::format(
              "unsupported operator version {}@{}, current {}@{}", name, expected, name, current))
    {}
    unsupported_operator_version(unsupported_operator_version &&) = default;
    unsupported_operator_version(const unsupported_operator_version &) = default;
    unsupported_operator_version &operator=(unsupported_operator_version &&) = default;
    unsupported_operator_version &operator=(const unsupported_operator_version &) = default;
    ~unsupported_operator_version() override = default;
};

class unknown_operator : public parsing_warning {
public:
    explicit unknown_operator(std::string_view name)
        : parsing_warning("unknown operator: '" + std::string(name) + "'")
    {}
    unknown_operator(unknown_operator &&) = default;
    unknown_operator(const unknown_operator &) = default;
    unknown_operator &operator=(unknown_operator &&) = default;
    unknown_operator &operator=(const unknown_operator &) = default;
    ~unknown_operator() override = default;
};

class unknown_generator : public parsing_warning {
public:
    explicit unknown_generator(std::string_view name)
        : parsing_warning("unknown generator: '" + std::string(name) + "'")
    {}
    unknown_generator(unknown_generator &&) = default;
    unknown_generator(const unknown_generator &) = default;
    unknown_generator &operator=(unknown_generator &&) = default;
    unknown_generator &operator=(const unknown_generator &) = default;
    ~unknown_generator() override = default;
};

class unknown_transformer : public parsing_warning {
public:
    explicit unknown_transformer(std::string_view name)
        : parsing_warning("unknown transformer: '" + std::string(name) + "'")
    {}
    unknown_transformer(unknown_transformer &&) = default;
    unknown_transformer(const unknown_transformer &) = default;
    unknown_transformer &operator=(unknown_transformer &&) = default;
    unknown_transformer &operator=(const unknown_transformer &) = default;
    ~unknown_transformer() override = default;
};

class malformed_object : public parsing_error {
public:
    explicit malformed_object(const std::string &what) : parsing_error("malformed object, " + what)
    {}
    malformed_object(malformed_object &&) = default;
    malformed_object(const malformed_object &) = default;
    malformed_object &operator=(malformed_object &&) = default;
    malformed_object &operator=(const malformed_object &) = default;
    ~malformed_object() override = default;
};

class bad_cast : public parsing_error {
public:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    bad_cast(std::string exp, std::string obt)
        : parsing_error("bad cast, expected '" + exp + "', obtained '" + obt + "'"),
          expected_(std::move(exp)), obtained_(std::move(obt))
    {}
    bad_cast(bad_cast &&) = default;
    bad_cast(const bad_cast &) = default;
    bad_cast &operator=(bad_cast &&) = default;
    bad_cast &operator=(const bad_cast &) = default;
    ~bad_cast() override = default;

    [[nodiscard]] std::string expected() const { return expected_; }
    [[nodiscard]] std::string obtained() const { return obtained_; }

protected:
    std::string expected_;
    std::string obtained_;
};

class missing_key : public parsing_error {
public:
    explicit missing_key(const std::string &key) : parsing_error("missing key '" + key + "'") {}
    missing_key(missing_key &&) = default;
    missing_key(const missing_key &) = default;
    missing_key &operator=(missing_key &&) = default;
    missing_key &operator=(const missing_key &) = default;
    ~missing_key() override = default;
};

class invalid_type : public parsing_error {
public:
    invalid_type(const std::string &key, const bad_cast &e)
        : parsing_error("invalid type '" + e.obtained() + "' for key '" + key + "', expected '" +
                        e.expected() + "'")
    {}
    invalid_type(const std::string &key, const std::string &type)
        : parsing_error("invalid type for key '" + key + "', expected '" + type + "'")
    {}

    invalid_type(invalid_type &&) = default;
    invalid_type(const invalid_type &) = default;
    invalid_type &operator=(invalid_type &&) = default;
    invalid_type &operator=(const invalid_type &) = default;
    ~invalid_type() override = default;
};

} // namespace ddwaf
