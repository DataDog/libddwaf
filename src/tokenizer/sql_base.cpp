// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/sql_base.hpp"
#include "regex_utils.hpp"
#include "utils.hpp"

#include <iostream>

// TODO: Split the tokenizer into different dialects

namespace ddwaf {

sql_dialect sql_dialect_from_type(std::string_view type)
{
    if (type == "mysql" || type == "mysql2") {
        return sql_dialect::mysql;
    }
    if (type == "postgresql") {
        return sql_dialect::postgresql;
    }
    if (type == "sqlite") {
        return sql_dialect::sqlite;
    }
    if (type == "oracle") {
        return sql_dialect::oracle;
    }
    if (type == "doctrine") {
        return sql_dialect::doctrine;
    }
    if (type == "hsqldb") {
        return sql_dialect::hsqldb;
    }
    return sql_dialect::generic;
}

std::ostream &operator<<(std::ostream &os, sql_token_type type)
{
    switch (type) {
    case sql_token_type::command:
        os << "command";
        break;
    case sql_token_type::identifier:
        os << "identifier";
        break;
    case sql_token_type::number:
        os << "number";
        break;
    case sql_token_type::string:
        os << "string";
        break;
    case sql_token_type::single_quoted_string:
        os << "single_quoted_string";
        break;
    case sql_token_type::double_quoted_string:
        os << "double_quoted_string";
        break;
    case sql_token_type::back_quoted_string:
        os << "back_quoted_string";
        break;
    case sql_token_type::dollar_quoted_string:
        os << "dollar_quoted_string";
        break;
    case sql_token_type::whitespace:
        os << "whitespace";
        break;
    case sql_token_type::asterisk:
        os << "asterisk";
        break;
    case sql_token_type::eol_comment:
        os << "eol_comment";
        break;
    case sql_token_type::parenthesis_open:
        os << "parenthesis_open";
        break;
    case sql_token_type::parenthesis_close:
        os << "parenthesis_close";
        break;
    case sql_token_type::comma:
        os << "comma";
        break;
    case sql_token_type::questionmark:
        os << "questionmark";
        break;
    case sql_token_type::label:
        os << "label";
        break;
    case sql_token_type::dot:
        os << "dot";
        break;
    case sql_token_type::query_end:
        os << "query_end";
        break;
    case sql_token_type::binary_operator:
        os << "binary_operator";
        break;
    case sql_token_type::bitwise_operator:
        os << "bitwise_operator";
        break;
    case sql_token_type::inline_comment:
        os << "inline_comment";
        break;
    case sql_token_type::array_open:
        os << "array_open";
        break;
    case sql_token_type::array_close:
        os << "array_close";
        break;
    case sql_token_type::unknown:
    default:
        os << "unknown";
        break;
    }
    return os;
}

} // namespace ddwaf
