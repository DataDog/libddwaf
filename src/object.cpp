// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "object.hpp"
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <new>

namespace ddwaf::detail {

char *copy_string(const char *str, std::size_t len)
{
    // TODO new char[len];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,hicpp-no-malloc)
    char *copy = static_cast<char *>(malloc(sizeof(char) * (len + 1)));
    if (copy == nullptr) {
        [[unlikely]] throw std::bad_alloc();
    }

    memcpy(copy, str, len);
    copy[len] = '\0';

    return copy;
}

} // namespace ddwaf::detail
