// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

// Fast searches for the first byte of a string that a transformer has to act
// on. Most strings need no transformation at all, so a transformer spends most
// of its time looking for such a byte: these searches examine 16 bytes at a
// time (SSE2 or NEON) and only return to the caller's byte loop on a hit.
//
// A predicate is written once, as a template over the type of its argument,
// with the functions below (eq, in_range, |, &). It is instantiated with
// `char` for the scalar paths, where they return 0 or 1, and with `bytes16` for
// the vector paths, where they return a per-byte mask; both paths therefore
// compute the same function by construction.
//
// Loads never go past the end of the string, which is not padded: the bytes
// that don't fill a whole block are examined with one more load that ends at
// the last byte (overlapping the previous one, whose bytes are masked out), and
// strings shorter than a block are scanned byte by byte.

#include <bit>
#include <cstddef>
#include <cstdint>

#if defined(LIBDDWAF_VECTORIZED_TRANSFORMERS)
#  if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#    define DDWAF_BYTE_SCAN_SSE2 1
#    include <emmintrin.h>
#  elif defined(__ARM_NEON) && defined(__aarch64__)
#    define DDWAF_BYTE_SCAN_NEON 1
#    include <arm_neon.h>
#  endif
#endif

#if defined(DDWAF_BYTE_SCAN_SSE2) || defined(DDWAF_BYTE_SCAN_NEON)
#  define DDWAF_BYTE_SCAN_VECTOR 1
#endif

// NOLINTBEGIN(portability-simd-intrinsics,cppcoreguidelines-pro-type-reinterpret-cast)
namespace ddwaf::transformer::byte_scan {

// Scalar building blocks, which return 0 or 1 (rather than bool, so that
// predicates can combine them with | and &, like the vector masks)
constexpr unsigned eq(char c, char value) { return c == value ? 1U : 0U; }
constexpr unsigned in_range(char c, char lo, char hi)
{
    return static_cast<uint8_t>(static_cast<uint8_t>(c) - static_cast<uint8_t>(lo)) <=
                   static_cast<uint8_t>(static_cast<uint8_t>(hi) - static_cast<uint8_t>(lo))
               ? 1U
               : 0U;
}

#if defined(DDWAF_BYTE_SCAN_VECTOR)

// The positions of a block of 16 bytes for which a predicate holds
class mask16 {
public:
#  if defined(DDWAF_BYTE_SCAN_SSE2)
    // One bit per byte
    static constexpr unsigned bits_per_byte = 1;
    using value_type = uint32_t;
#  else
    // Four bits per byte (NEON has no movemask)
    static constexpr unsigned bits_per_byte = 4;
    using value_type = uint64_t;
#  endif

    explicit mask16(value_type value) : value_(value) {}

    [[nodiscard]] bool any() const { return value_ != 0; }
    // Index of the first position, only valid if any()
    [[nodiscard]] std::size_t first() const
    { return static_cast<std::size_t>(std::countr_zero(value_)) / bits_per_byte; }
    // Drops the first n positions (n < 16)
    [[nodiscard]] mask16 skip(std::size_t n) const
    { return mask16{value_ & (~value_type{0} << (n * bits_per_byte))}; }

protected:
    value_type value_;
};

// A block of 16 bytes, or a per-byte mask (0x00 or 0xFF) over such a block
class bytes16 {
public:
    static constexpr std::size_t size = 16;

#  if defined(DDWAF_BYTE_SCAN_SSE2)
    using native_type = __m128i;
    static bytes16 load(const char *p)
    { return bytes16{_mm_loadu_si128(reinterpret_cast<const __m128i *>(p))}; }
    void store(char *p) const { _mm_storeu_si128(reinterpret_cast<__m128i *>(p), value_); }
    static bytes16 splat(char c) { return bytes16{_mm_set1_epi8(c)}; }

    [[nodiscard]] bytes16 eq(char value) const
    { return bytes16{_mm_cmpeq_epi8(value_, _mm_set1_epi8(value))}; }
    [[nodiscard]] bytes16 in_range(char lo, char hi) const
    {
        // Unsigned (v - lo) <= (hi - lo), with min_epu8 since SSE2 has no
        // unsigned comparison
        const __m128i offset = _mm_sub_epi8(value_, _mm_set1_epi8(lo));
        const __m128i bound = _mm_set1_epi8(static_cast<char>(hi - lo));
        return bytes16{_mm_cmpeq_epi8(_mm_min_epu8(offset, bound), offset)};
    }
    friend bytes16 operator|(bytes16 a, bytes16 b)
    { return bytes16{_mm_or_si128(a.value_, b.value_)}; }
    friend bytes16 operator&(bytes16 a, bytes16 b)
    { return bytes16{_mm_and_si128(a.value_, b.value_)}; }
    [[nodiscard]] mask16 mask() const
    { return mask16{static_cast<uint32_t>(_mm_movemask_epi8(value_))}; }
#  else
    using native_type = uint8x16_t;
    static bytes16 load(const char *p)
    { return bytes16{vld1q_u8(reinterpret_cast<const uint8_t *>(p))}; }
    void store(char *p) const { vst1q_u8(reinterpret_cast<uint8_t *>(p), value_); }
    static bytes16 splat(char c) { return bytes16{vdupq_n_u8(static_cast<uint8_t>(c))}; }

    [[nodiscard]] bytes16 eq(char value) const
    { return bytes16{vceqq_u8(value_, vdupq_n_u8(static_cast<uint8_t>(value)))}; }
    [[nodiscard]] bytes16 in_range(char lo, char hi) const
    {
        const uint8x16_t offset = vsubq_u8(value_, vdupq_n_u8(static_cast<uint8_t>(lo)));
        return bytes16{vcleq_u8(offset, vdupq_n_u8(static_cast<uint8_t>(hi - lo)))};
    }
    friend bytes16 operator|(bytes16 a, bytes16 b) { return bytes16{vorrq_u8(a.value_, b.value_)}; }
    friend bytes16 operator&(bytes16 a, bytes16 b) { return bytes16{vandq_u8(a.value_, b.value_)}; }
    [[nodiscard]] mask16 mask() const
    {
        // Narrow each 16-bit lane by 4 bits: one nibble per byte
        const uint8x8_t narrowed = vshrn_n_u16(vreinterpretq_u16_u8(value_), 4);
        return mask16{vget_lane_u64(vreinterpret_u64_u8(narrowed), 0)};
    }
#  endif

protected:
    explicit bytes16(native_type value) : value_(value) {}

    native_type value_;
};

inline bytes16 eq(bytes16 v, char value) { return v.eq(value); }
inline bytes16 in_range(bytes16 v, char lo, char hi) { return v.in_range(lo, hi); }

#endif // DDWAF_BYTE_SCAN_VECTOR

// Returns the index of the first byte at or after start for which
// Pred::match(char) holds, or size if there is none.
template <typename Pred>
std::size_t find_first(const char *data, std::size_t size, std::size_t start = 0)
{
    std::size_t i = start;
#if defined(DDWAF_BYTE_SCAN_VECTOR)
    if (size >= bytes16::size) {
        for (; i + bytes16::size <= size; i += bytes16::size) {
            const auto m = Pred::match(bytes16::load(data + i)).mask();
            if (m.any()) {
                return i + m.first();
            }
        }

        if (i < size) {
            const std::size_t base = size - bytes16::size;
            const auto m = Pred::match(bytes16::load(data + base)).mask().skip(i - base);
            if (m.any()) {
                return base + m.first();
            }
        }
        return size;
    }
#endif

    for (; i < size; ++i) {
        if (Pred::match(data[i]) != 0) {
            return i;
        }
    }
    return size;
}

// Returns the index of the first byte at or after start for which either
// Pred::match(char current, char next) holds, if it isn't the last byte, or
// Pred::match_last(char current) holds, if it is; or size if there is none.
template <typename Pred>
std::size_t find_first_pair(const char *data, std::size_t size, std::size_t start = 0)
{
    std::size_t i = start;
    if (i >= size) {
        return size;
    }

#if defined(DDWAF_BYTE_SCAN_VECTOR)
    // A block needs the byte that follows it
    constexpr std::size_t span = bytes16::size + 1;
    if (size >= span) {
        for (; i + span <= size; i += bytes16::size) {
            const auto m = Pred::match(bytes16::load(data + i), bytes16::load(data + i + 1)).mask();
            if (m.any()) {
                return i + m.first();
            }
        }

        if (i < size - 1) {
            const std::size_t base = size - span;
            const auto m = Pred::match(bytes16::load(data + base), bytes16::load(data + base + 1))
                               .mask()
                               .skip(i - base);
            if (m.any()) {
                return base + m.first();
            }
            i = size - 1;
        }
    }
#endif

    for (; i + 1 < size; ++i) {
        if (Pred::match(data[i], data[i + 1]) != 0) {
            return i;
        }
    }

    return Pred::match_last(data[size - 1]) ? size - 1 : size;
}

} // namespace ddwaf::transformer::byte_scan
// NOLINTEND(portability-simd-intrinsics,cppcoreguidelines-pro-type-reinterpret-cast)
