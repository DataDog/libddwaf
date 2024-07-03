// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
//
// This code has been adapted from OpenSSL.
//
// Copyright 2004-2023 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//

#include "sha256.hpp"

namespace ddwaf {
namespace {

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
/*
 * Note that FIPS180-2 discusses "Truncation of the Hash Function Output."
 * default: case below covers for it. It's not clear however if it's
 * permitted to truncate to amount of bytes not divisible by 4. I bet not,
 * but if it is, then default: case shall be extended. For reference.
 * Idea behind separate cases for pre-defined lengths is to let the
 * compiler decide if it's appropriate to unroll small loops.
 */
#define ROTATE(a, n) (((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))

#define CHAR_TO_UINT32(c, l)                                                                       \
    {                                                                                              \
        (l) = ((static_cast<uint32_t>(*((c)++))) << 24);                                           \
        (l) |= ((static_cast<uint32_t>(*((c)++))) << 16);                                          \
        (l) |= ((static_cast<uint32_t>(*((c)++))) << 8);                                           \
        (l) |= ((static_cast<uint32_t>(*((c)++))));                                                \
    }

#define UINT8_TO_HEX_CHAR(u) static_cast<char>((u) < 10 ? (u) + '0' : (u)-10 + 'a')

/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#define Sigma0(x) (ROTATE((x), 30) ^ ROTATE((x), 19) ^ ROTATE((x), 10))
#define Sigma1(x) (ROTATE((x), 26) ^ ROTATE((x), 21) ^ ROTATE((x), 7))
#define sigma0(x) (ROTATE((x), 25) ^ ROTATE((x), 14) ^ ((x) >> 3))
#define sigma1(x) (ROTATE((x), 15) ^ ROTATE((x), 13) ^ ((x) >> 10))
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROUND_00_15(i, a, b, c, d, e, f, g, h)                                                     \
    {                                                                                              \
        T1 += (h) + Sigma1(e) + Ch(e, f, g) + K256[i];                                             \
        (h) = Sigma0(a) + Maj(a, b, c);                                                            \
        (d) += T1;                                                                                 \
        (h) += T1;                                                                                 \
    }

#define ROUND_16_63(i, a, b, c, d, e, f, g, h, X)                                                  \
    {                                                                                              \
        s0 = (X)[((i) + 1) & 0x0f];                                                                \
        s0 = sigma0(s0);                                                                           \
        s1 = (X)[((i) + 14) & 0x0f];                                                               \
        s1 = sigma1(s1);                                                                           \
        T1 = (X)[(i) & 0x0f] += s0 + s1 + (X)[((i) + 9) & 0x0f];                                   \
        ROUND_00_15(i, a, b, c, d, e, f, g, h);                                                    \
    }

// NOLINTEND(cppcoreguidelines-macro-usage)

constexpr std::array<uint32_t, 64> K256 = {0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL,
    0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL,
    0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL,
    0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL,
    0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

} // namespace

sha256_hash &sha256_hash::operator<<(std::string_view str)
{
    uint8_t *p;
    uint32_t l;
    size_t n;

    if (str.length() == 0) {
        return *this;
    }
    auto len = static_cast<uint32_t>(str.length());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const uint8_t *>(str.data());

    l = (length_low + ((len) << 3)) & 0xffffffffUL;
    if (l < length_low) { /* overflow */
        length_high++;
    }
    length_high += (len >> 29); /* might cause compiler warning on
                                 * 16-bit */
    length_low = l;

    n = num;
    if (n != 0) {
        p = buffer.data();

        if (len >= block_size || len + n >= block_size) {
            memcpy(p + n, data, block_size - n);
            sha_block_data_order(p, 1);
            n = block_size - n;
            data += n;
            len -= n;
            num = 0;
            memset(p, 0, block_size); /* keep it zeroed */
        } else {
            memcpy(p + n, data, len);
            num += len;
            return *this;
        }
    }

    n = len / block_size;
    if (n > 0) {
        sha_block_data_order(data, n);
        n *= block_size;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = buffer.data();
        num = len;
        memcpy(p, data, len);
    }
    return *this;
}

template <std::size_t N>
std::string sha256_hash::digest()
    requires(N % 8 == 0 && N <= 64)
{
    std::array<char, N> final_digest{0};
    write_digest(final_digest);
    return std::string{final_digest.data(), N};
}

template std::string sha256_hash::digest<64>();
template std::string sha256_hash::digest<8>();

template <std::size_t N>
void sha256_hash::write_digest(std::array<char, N> &output)
    requires(N % 8 == 0 && N <= 64)
{
    auto *p = buffer.data();
    size_t n = num;

    p[n] = 0x80; /* there is always room for one */
    n++;

    if (n > (block_size - 8)) {
        memset(p + n, 0, block_size - n);
        n = 0;
        sha_block_data_order(p, 1);
    }
    memset(p + n, 0, block_size - 8 - n);

    p += block_size - 8;

    *(p++) = static_cast<uint8_t>((length_high >> 24) & 0xff);
    *(p++) = static_cast<uint8_t>((length_high >> 16) & 0xff);
    *(p++) = static_cast<uint8_t>((length_high >> 8) & 0xff);
    *(p++) = static_cast<uint8_t>(length_high & 0xff);

    *(p++) = static_cast<uint8_t>((length_low >> 24) & 0xff);
    *(p++) = static_cast<uint8_t>((length_low >> 16) & 0xff);
    *(p++) = static_cast<uint8_t>((length_low >> 8) & 0xff);
    *(p++) = static_cast<uint8_t>(length_low & 0xff);

    p -= block_size;

    sha_block_data_order(p, 1);
    num = 0;
    memset(p, 0, block_size);

    for (unsigned int nn = 0; nn < N; nn += 8) {
        uint32_t ll = hash[nn >> 3];
        output[nn + 0] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 28) & 0x0f));
        output[nn + 1] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 24) & 0x0f));
        output[nn + 2] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 20) & 0x0f));
        output[nn + 3] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 16) & 0x0f));
        output[nn + 4] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 12) & 0x0f));
        output[nn + 5] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 8) & 0x0f));
        output[nn + 6] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>((ll >> 4) & 0x0f));
        output[nn + 7] = UINT8_TO_HEX_CHAR(static_cast<uint8_t>(ll & 0x0f));
    }

    // Reset the hasher and return
    reset();
}

void sha256_hash::sha_block_data_order(const uint8_t *data, size_t len)
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    unsigned int e;
    unsigned int f;
    unsigned int g;
    unsigned int h;
    unsigned int s0;
    unsigned int s1;
    unsigned int T1;
    std::array<uint32_t, 16> X{0};
    int i;

    while ((len--) != 0) {

        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];
        f = hash[5];
        g = hash[6];
        h = hash[7];

        uint32_t l;

        CHAR_TO_UINT32(data, l);
        T1 = X[0] = l;
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        CHAR_TO_UINT32(data, l);
        T1 = X[1] = l;
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        CHAR_TO_UINT32(data, l);
        T1 = X[2] = l;
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        CHAR_TO_UINT32(data, l);
        T1 = X[3] = l;
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        CHAR_TO_UINT32(data, l);
        T1 = X[4] = l;
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        CHAR_TO_UINT32(data, l);
        T1 = X[5] = l;
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        CHAR_TO_UINT32(data, l);
        T1 = X[6] = l;
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        CHAR_TO_UINT32(data, l);
        T1 = X[7] = l;
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        CHAR_TO_UINT32(data, l);
        T1 = X[8] = l;
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        CHAR_TO_UINT32(data, l);
        T1 = X[9] = l;
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        CHAR_TO_UINT32(data, l);
        T1 = X[10] = l;
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        CHAR_TO_UINT32(data, l);
        T1 = X[11] = l;
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        CHAR_TO_UINT32(data, l);
        T1 = X[12] = l;
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        CHAR_TO_UINT32(data, l);
        T1 = X[13] = l;
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        CHAR_TO_UINT32(data, l);
        T1 = X[14] = l;
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        CHAR_TO_UINT32(data, l);
        T1 = X[15] = l;
        ROUND_00_15(15, b, c, d, e, f, g, h, a);

        for (i = 16; i < 64; i += 8) {
            ROUND_16_63(i + 0, a, b, c, d, e, f, g, h, X);
            ROUND_16_63(i + 1, h, a, b, c, d, e, f, g, X);
            ROUND_16_63(i + 2, g, h, a, b, c, d, e, f, X);
            ROUND_16_63(i + 3, f, g, h, a, b, c, d, e, X);
            ROUND_16_63(i + 4, e, f, g, h, a, b, c, d, X);
            ROUND_16_63(i + 5, d, e, f, g, h, a, b, c, X);
            ROUND_16_63(i + 6, c, d, e, f, g, h, a, b, X);
            ROUND_16_63(i + 7, b, c, d, e, f, g, h, a, X);
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
}

} // namespace ddwaf
