// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace ddwaf {

enum class sql_flavour { generic, mysql, postgresql, oracle, sqlite, hsqldb, doctrine };

enum class sql_token_type {
    command,
    hex,
    number,
    string,
    single_quoted_string,
    double_quoted_string,
    back_quoted_string,
    whitespace,
    asterisk,
    eol_comment,
    parenthesis_open,
    parenthesis_close,
    comma,
    questionmark,
    label,
    dot,
    query_end,
    binary_operator,
    bitwise_operator,
    inline_comment,
};

struct sql_token {
    sql_token_type type;
    std::string_view str;
    std::size_t index;
};

inline sql_flavour sql_flavour_from_type(std::string_view type)
{
    if (type == "mysql" || type == "mysql2") {
        return sql_flavour::mysql;
    }
    if (type == "postgresql") {
        return sql_flavour::postgresql;
    }
    if (type == "sqlite") {
        return sql_flavour::sqlite;
    }
    if (type == "oracle") {
        return sql_flavour::oracle;
    }
    if (type == "doctrine") {
        return sql_flavour::doctrine;
    }
    if (type == "hsqldb") {
        return sql_flavour::hsqldb;
    }
    return sql_flavour::generic;
}

std::vector<sql_token> sql_tokenize(std::string_view resource, sql_flavour flavour);

} // namespace ddwaf
