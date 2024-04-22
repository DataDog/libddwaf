// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "tokenizer/mysql.hpp"
#include "tokenizer/pgsql.hpp"
#include "tokenizer/sql_base.hpp"
#include "tokenizer/sql_standard.hpp"
#include "tokenizer/sqlite.hpp"

ddwaf::sql_dialect dialect = ddwaf::sql_dialect::standard;

extern "C" int LLVMFuzzerInitialize(const int *argc, char ***argv)
{
    for (int i = 0; i < *argc; i++) {
        std::string_view arg = (*argv)[i];
        if (arg.starts_with("--dialect=")) {
            dialect = ddwaf::sql_dialect_from_type(arg.substr(sizeof("--dialect=") - 1));
            std::cout << "Dialect: " << dialect << '\n';
            break;
        }
    }
    return 0;
}

template <typename T> [[clang::optnone]] void tokenize(std::string_view query)
{
    T tokenizer(query);
    auto tokens = tokenizer.tokenize();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string_view query{reinterpret_cast<const char *>(bytes), size};
    switch (dialect) {
    case ddwaf::sql_dialect::mysql:
        tokenize<ddwaf::mysql_tokenizer>(query);
        break;
    case ddwaf::sql_dialect::postgresql:
        tokenize<ddwaf::pgsql_tokenizer>(query);
        break;
    case ddwaf::sql_dialect::sqlite:
        tokenize<ddwaf::sqlite_tokenizer>(query);
        break;
    default:
        tokenize<ddwaf::sql_standard_tokenizer>(query);
    }
    return 0;
}
