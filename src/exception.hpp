// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace ddwaf {

class exception : public std::exception {
public:
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

protected:
    explicit exception(std::string what) : what_(std::move(what)) {}

    const std::string what_;
};

class unsupported_version : public exception {
public:
    unsupported_version() : exception(std::string()){};
};

class parsing_error : public exception {
public:
    explicit parsing_error(const std::string &what) : exception(what) {}
};

class malformed_object : public exception {
public:
    explicit malformed_object(const std::string &what) : exception("malformed object, " + what) {}
};

class bad_cast : public exception {
public:
    bad_cast(std::string exp, std::string obt)
        : exception("bad cast, expected '" + exp + "', obtained '" + obt + "'"),
          expected_(std::move(exp)), obtained_(std::move(obt))
    {}

    [[nodiscard]] std::string expected() const { return expected_; }
    [[nodiscard]] std::string obtained() const { return obtained_; }

protected:
    const std::string expected_;
    const std::string obtained_;
};

class missing_key : public parsing_error {
public:
    explicit missing_key(const std::string &key) : parsing_error("missing key '" + key + "'") {}
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
};

class timeout_exception : public exception {
public:
    timeout_exception() : exception({}) {}
};

} // namespace ddwaf
