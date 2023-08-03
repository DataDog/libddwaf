// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/lowercase.hpp"

#ifdef __SSE2__
#  include <immintrin.h>
#endif

namespace ddwaf::transformer {

#ifndef __SSE2__
bool lowercase::transform_impl(cow_string &str)
{
    std::size_t pos = 0;

    // First loop looking for the first non-lowercase char
    for (; pos < str.length() && (str.at(pos) < 'A' || str.at(pos) > 'Z'); ++pos) {}

    //  If we're checking whether we need to do change, finding such a char mean we need to
    //  do so (we return true if we need to update)
    if (pos == str.length()) {
        return false;
    }

    //  If we're mutating the string, then we have the starting offset
    for (; pos < str.length(); ++pos) { str[pos] = tolower(str.at(pos)); }

    return true;
}

#else // defined(__SSE2__)

static inline bool is_lowercase(const char *input, std::size_t size)
{
    if (size == 0) {
        return true;
    }

    __m128i sse_mask_lower_bound = _mm_set1_epi8('A');
    __m128i sse_mask_upper_bound = _mm_set1_epi8('Z');

    std::size_t aligned_size = size & ~0xF;

    __m128i cmp_result_final = _mm_setzero_si128();
    for (std::size_t i = 0; i < aligned_size; i += 16) {
        __m128i input_data = _mm_loadu_si128((__m128i *)(input + i));

        __m128i cmp_upper = _mm_cmpgt_epi8(input_data, sse_mask_lower_bound); // Greater than 'A'
        __m128i cmp_lower = _mm_cmpgt_epi8(sse_mask_upper_bound, input_data); // Less than 'Z'
        __m128i cmp_result =
            _mm_and_si128(cmp_upper, cmp_lower); // Combine the two comparison results
        cmp_result_final = _mm_or_si128(cmp_result_final, cmp_result);
    }

    bool is_lowercase =
        _mm_movemask_epi8(_mm_cmpeq_epi8(cmp_result_final, _mm_setzero_si128())) == 0xFFFF;

    for (std::size_t i = aligned_size; i < size; i++) { is_lowercase &= !isupper(input[i]); }

    return is_lowercase;
}

bool lowercase::transform_impl(cow_string &str)
{
    const char *cinput = str.data();
    auto size = str.length();

    if (is_lowercase(cinput, size)) {
        return false;
    }

    char *input = str.modifiable_data();

    __m128i sse_mask_upper_bound = _mm_set1_epi8('Z');
    __m128i sse_mask_lower_bound = _mm_set1_epi8('A');
    __m128i sse_addition_value = _mm_set1_epi8(0x20); // value to add to convert up to lc

    std::size_t aligned_size = size & ~0xF;

    for (std::size_t i = 0; i < aligned_size; i += 16) {
        __m128i input_data = _mm_loadu_si128((__m128i *)(input + i));

        __m128i cmp_upper = _mm_cmpgt_epi8(input_data, sse_mask_lower_bound); // > 'A'
        __m128i cmp_lower = _mm_cmpgt_epi8(sse_mask_upper_bound, input_data); // < 'Z'
        __m128i cmp_result = _mm_and_si128(cmp_upper, cmp_lower);

        __m128i result = _mm_add_epi8(input_data, _mm_and_si128(cmp_result, sse_addition_value));
        _mm_storeu_si128((__m128i *)(input + i), result);
    }

    for (std::size_t i = aligned_size; i < size; i++) {
        char c = input[i];
        input[i] = tolower(c);
    }

    return true;
}
#endif

} // namespace ddwaf::transformer
