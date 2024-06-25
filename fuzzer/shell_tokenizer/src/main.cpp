// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "tokenizer/shell.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string_view query{reinterpret_cast<const char *>(bytes), size};
    ddwaf::shell_tokenizer tokenizer(query);
    auto tokens = tokenizer.tokenize();

    // Force the compiler to not optimize away tokens
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("" : "+m"(tokens) : : "memory");

    return 0;
}
