// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

namespace ddwaf {

class sha256_hash {
public:
    sha256_hash() = default;
    ~sha256_hash() = default;
    sha256_hash(const sha256_hash &) = delete;
    sha256_hash(sha256_hash &&) = delete;
    sha256_hash &operator=(const sha256_hash &) = delete;
    sha256_hash &operator=(sha256_hash &&) noexcept = delete;

    sha256_hash &operator<<(std::string_view str);
    [[nodiscard]] std::string digest();

    void reset()
    {
        hash = initial_hash_values;
        length_low = 0;
        length_high = 0;
        buffer = {0};
        num = {0};
    }

protected:
    static constexpr std::array<uint32_t, 8> initial_hash_values{0x6a09e667, 0xbb67ae85, 0x3c6ef372,
        0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    void sha_block_data_order(const uint8_t *data, size_t len);

    std::array<uint32_t, 8> hash{initial_hash_values};
    uint32_t length_low{0};
    uint32_t length_high{0};
    std::array<uint8_t, 128> buffer{0};
    uint32_t num{0};
};

} // namespace ddwaf
