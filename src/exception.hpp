// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <stdexcept>
#include <string>

namespace ddwaf
{

class exception : public std::exception
{
public:
    const char* what() const noexcept { return what_.c_str(); }

protected:
    exception(const std::string& what) : what_(what) {}

protected:
    const std::string what_;
};

class unsupported_version : public exception
{
public:
    unsupported_version() : exception(std::string()) {};
};

class parsing_error : public exception
{
public:
    parsing_error(const std::string& what) : exception(what) {}
};

class malformed_object : public exception
{
public:
    malformed_object(const std::string& what) : exception("malformed object," + what) {}
};

class bad_cast : public exception
{
public:
    bad_cast(const std::string& exp, const std::string& obt) : exception("bad cast, expected '" + exp + "', obtained '" + obt + "'"),
                                                               expected_(exp),
                                                               obtained_(obt) {}

    const std::string expected() const { return expected_; }
    const std::string obtained() const { return obtained_; }

protected:
    const std::string expected_;
    const std::string obtained_;
};

class missing_key : public parsing_error
{
public:
    missing_key(const std::string& key) : parsing_error("missing key '" + key + "'") {}
};

class invalid_type : public parsing_error
{
public:
    invalid_type(const std::string& key, const bad_cast& e) : parsing_error("invalid type '" + e.obtained() + "' for key '" + key + "', expected '" + e.expected() + "'") {}
    invalid_type(const std::string& key, const std::string& type) : parsing_error("invalid type for key '" + key + "', expected '" + type + "'") {}
};

class timeout_exception : public exception
{
public:
    timeout_exception(): exception({}) {}
};

}
