// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#if defined(__SSE2__) && defined(LIBDDWAF_VECTORIZED_TRANSFORMERS)
#  include <immintrin.h>
#endif

#include "transformer/lowercase.hpp"

namespace ddwaf::transformer {

#if !defined(__SSE2__) || !defined(LIBDDWAF_VECTORIZED_TRANSFORMERS)
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

#else // defined(__SSE2__) && defined(LIBDDWAF_VECTORIZED_TRANSFORMERS)
bool lowercase::needs_transform(std::string_view str)
{
    if (str.empty()) {
        return false;
    }

    const char *input = str.data();

    const __m128i sse_mask_lower_bound = _mm_set1_epi8('A' - 1);
    const __m128i sse_mask_upper_bound = _mm_set1_epi8('Z' + 1);

    const std::size_t aligned_size = str.size() & ~0xF;

    bool has_uppercase = false;
    for (std::size_t i = 0; i < aligned_size && !has_uppercase; i += 16) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
        const __m128i input_data = _mm_loadu_si128((__m128i *)(input + i));

        const __m128i cmp_upper =
            _mm_cmpgt_epi8(input_data, sse_mask_lower_bound); // Greater than 'A'
        const __m128i cmp_lower = _mm_cmpgt_epi8(sse_mask_upper_bound, input_data); // Less than 'Z'
        const __m128i cmp_result =
            _mm_and_si128(cmp_upper, cmp_lower); // Combine the two comparison results
        has_uppercase =
            _mm_movemask_epi8(_mm_cmpeq_epi8(cmp_result, _mm_setzero_si128())) != 0xFFFF;
    }

    for (std::size_t i = aligned_size; i < str.size() && !has_uppercase; i++) {
        has_uppercase = isupper(input[i]);
    }

    return has_uppercase;
}

bool lowercase::transform_impl(cow_string &str)
{
    auto size = str.length();
    char *input = str.modifiable_data();

    const __m128i sse_mask_upper_bound = _mm_set1_epi8('Z' + 1);
    const __m128i sse_mask_lower_bound = _mm_set1_epi8('A' - 1);
    const __m128i sse_addition_value = _mm_set1_epi8(0x20); // value to add to convert up to lc

    const std::size_t aligned_size = size & ~0xF;

    for (std::size_t i = 0; i < aligned_size; i += 16) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
        const __m128i input_data = _mm_loadu_si128((__m128i *)(input + i));

        const __m128i cmp_upper = _mm_cmpgt_epi8(input_data, sse_mask_lower_bound); // > 'A' - 1
        const __m128i cmp_lower = _mm_cmpgt_epi8(sse_mask_upper_bound, input_data); // < 'Z' + 1
        const __m128i cmp_result = _mm_and_si128(cmp_upper, cmp_lower);

        const __m128i result =
            _mm_add_epi8(input_data, _mm_and_si128(cmp_result, sse_addition_value));
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
        _mm_storeu_si128((__m128i *)(input + i), result);
    }

    for (std::size_t i = aligned_size; i < size; i++) {
        const char c = input[i];
        input[i] = tolower(c);
    }

    return true;
}
#endif

} // namespace ddwaf::transformer
