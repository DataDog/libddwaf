// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

#include "fmt/core.h"
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

constexpr std::string_view uuid_fmt_str = "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:"
                                          "02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}";

} // namespace

std::string uuidv4_generate_pseudo()
{
    static auto rng = init_rng();

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

    return ddwaf::fmt::format(uuid_fmt_str, uuid_bytes.byte[0], uuid_bytes.byte[1],
        uuid_bytes.byte[2], uuid_bytes.byte[3], uuid_bytes.byte[4], uuid_bytes.byte[5],
        uuid_bytes.byte[6], uuid_bytes.byte[7], uuid_bytes.byte[8], uuid_bytes.byte[9],
        uuid_bytes.byte[10], uuid_bytes.byte[11], uuid_bytes.byte[12], uuid_bytes.byte[13],
        uuid_bytes.byte[14], uuid_bytes.byte[15]);
}

} // namespace ddwaf
