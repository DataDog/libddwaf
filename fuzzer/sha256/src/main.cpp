// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "sha256.hpp"

extern "C" int LLVMFuzzerInitialize(const int * /*argc*/, char *** /*argv*/) { return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    ddwaf::sha256_hash hasher;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    hasher << std::string_view{reinterpret_cast<const char *>(bytes), size};
    auto str = hasher.digest();

    // Force the compiler to not optimize away str
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("" : "+m"(str) : : "memory");

    return 0;
}
