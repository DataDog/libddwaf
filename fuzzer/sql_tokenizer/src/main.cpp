// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "tokenizer/generic_sql.hpp"
#include "tokenizer/mysql.hpp"
#include "tokenizer/pgsql.hpp"
#include "tokenizer/sql_base.hpp"
#include "tokenizer/sqlite.hpp"

ddwaf::sql_dialect dialect = ddwaf::sql_dialect::generic;

extern "C" int LLVMFuzzerInitialize(const int *argc, char ***argv)
{
    for (int i = 0; i < *argc; i++) {
        std::string_view arg = (*argv)[i];
        if (arg.starts_with("--dialect=")) {
            dialect = ddwaf::sql_dialect_from_type(arg.substr(sizeof("--dialect=") - 1));
            break;
        }
    }
    return 0;
}

template <typename T> [[clang::optnone]] void tokenize(std::string_view query)
{
    T tokenizer(query);
    auto tokens = tokenizer.tokenize();
    // Force the compiler to not optimize away tokens
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("" : "+m"(tokens) : : "memory");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string_view query{reinterpret_cast<const char *>(bytes), size};
    switch (dialect) {
    case ddwaf::sql_dialect::mysql:
        tokenize<ddwaf::mysql_tokenizer>(query);
        break;
    case ddwaf::sql_dialect::pgsql:
        tokenize<ddwaf::pgsql_tokenizer>(query);
        break;
    case ddwaf::sql_dialect::sqlite:
        tokenize<ddwaf::sqlite_tokenizer>(query);
        break;
    default:
        tokenize<ddwaf::generic_sql_tokenizer>(query);
    }
    return 0;
}
