// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

#include "uuid.hpp"

namespace ddwaf {

namespace {

auto init_rng()
{
    auto seed = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
    return std::mt19937_64{seed};
}

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

    std::stringstream ss;
    ss << std::hex;
    for (unsigned i = 0; i < 16; ++i) {
        ss << std::setfill('0') << std::setw(2) << static_cast<unsigned>(uuid_bytes.byte[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            ss << '-';
        }
    }

    return ss.str();
}

} // namespace ddwaf
