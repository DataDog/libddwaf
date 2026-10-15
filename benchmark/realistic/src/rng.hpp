// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

// Self-contained deterministic PRNG (xoshiro256**, seeded by splitmix64).
// std:: distributions are deliberately avoided: their output is
// implementation-defined and would make inputs differ between standard
// libraries.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bench {

class rng {
public:
    explicit rng(uint64_t seed)
    {
        for (auto &s : s_) {
            seed += 0x9e3779b97f4a7c15ULL;
            uint64_t z = seed;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
            s = z ^ (z >> 31);
        }
    }

    uint64_t next()
    {
        const uint64_t result = rotl(s_[1] * 5, 7) * 9;
        const uint64_t t = s_[1] << 17;
        s_[2] ^= s_[0];
        s_[3] ^= s_[1];
        s_[1] ^= s_[2];
        s_[0] ^= s_[3];
        s_[2] ^= t;
        s_[3] = rotl(s_[3], 45);
        return result;
    }

    // uniform in [0, n)
    uint64_t below(uint64_t n) { return n == 0 ? 0 : next() % n; }
    // uniform in [lo, hi]
    int64_t range(int64_t lo, int64_t hi)
    {
        return lo + static_cast<int64_t>(below(static_cast<uint64_t>(hi - lo + 1)));
    }
    // true with probability num/den
    bool chance(uint64_t num, uint64_t den) { return below(den) < num; }

    template <typename T> const T &pick(const std::vector<T> &v) { return v[below(v.size())]; }
    template <typename T, std::size_t N> const T &pick(const T (&v)[N]) { return v[below(N)]; }

    std::string hex(std::size_t len)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out(len, '0');
        for (auto &c : out) { c = digits[below(16)]; }
        return out;
    }

    std::string alnum(std::size_t len)
    {
        static constexpr char chars[] =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string out(len, 'a');
        for (auto &c : out) { c = chars[below(sizeof(chars) - 1)]; }
        return out;
    }

    // base64 / base64url of `bytes` random bytes
    std::string base64(std::size_t bytes, bool url = false)
    {
        std::string raw(bytes, '\0');
        for (auto &c : raw) { c = static_cast<char>(below(256)); }
        return encode_base64(raw, url);
    }

    static std::string encode_base64(std::string_view raw, bool url = false)
    {
        const char *tbl = url ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                              : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve((raw.size() + 2) / 3 * 4);
        std::size_t i = 0;
        for (; i + 2 < raw.size(); i += 3) {
            uint32_t v = (uint8_t)raw[i] << 16 | (uint8_t)raw[i + 1] << 8 | (uint8_t)raw[i + 2];
            out += tbl[(v >> 18) & 63];
            out += tbl[(v >> 12) & 63];
            out += tbl[(v >> 6) & 63];
            out += tbl[v & 63];
        }
        if (i + 1 == raw.size()) {
            uint32_t v = (uint8_t)raw[i] << 16;
            out += tbl[(v >> 18) & 63];
            out += tbl[(v >> 12) & 63];
            if (!url) { out += "=="; }
        } else if (i + 2 == raw.size()) {
            uint32_t v = (uint8_t)raw[i] << 16 | (uint8_t)raw[i + 1] << 8;
            out += tbl[(v >> 18) & 63];
            out += tbl[(v >> 12) & 63];
            out += tbl[(v >> 6) & 63];
            if (!url) { out += '='; }
        }
        return out;
    }

    std::string uuid()
    {
        std::string h = hex(32);
        h[12] = '4';
        h[16] = "89ab"[below(4)];
        return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" +
               h.substr(16, 4) + "-" + h.substr(20, 12);
    }

private:
    static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
    uint64_t s_[4]{};
};

} // namespace bench
