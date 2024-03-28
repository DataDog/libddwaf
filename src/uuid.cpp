// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

#include "uuid.hpp"

namespace ddwaf {

namespace {
// System clock is used to provide a more unique seed compared to the
// monotonic clock, which is backed by a steady clock, in practice it
// likely doesn't make a difference.
using clock = std::chrono::system_clock;

auto init_rng()
{
    return std::mt19937_64{static_cast<uint64_t>(clock::now().time_since_epoch().count())};
}

} // namespace

std::string uuidv4_generate_pseudo()
{
    static thread_local auto rng = init_rng();

    union {
        // NOLINTNEXTLINE
        uint8_t byte[16];
        // NOLINTNEXTLINE
        uint64_t qword[2];
    } uuid_bytes{};

    uuid_bytes.qword[0] = rng();
    uuid_bytes.qword[1] = rng();

    uuid_bytes.byte[6] = 0x4F & (0x40 | uuid_bytes.byte[4]);
    uuid_bytes.byte[8] = 0x1b;

    std::string result;
    result.resize(36);
    char *buffer = result.data();
    static constexpr auto hex_chars = std::array<char, 17>{"0123456789abcdef"};

    for (int i = 0, j = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            buffer[j++] = '-';
        }
        buffer[j++] = hex_chars[(uuid_bytes.byte[i] >> 4) & 0x0F];
        buffer[j++] = hex_chars[uuid_bytes.byte[i] & 0x0F];
    }
    return result;
}

} // namespace ddwaf
