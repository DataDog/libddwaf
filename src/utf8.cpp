// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

extern "C" {
#include <stdint.h>
#include <utf8proc.h>
}

#include "cow_string.hpp"
#include "utf8.hpp"

namespace ddwaf::utf8 {

namespace {

int8_t find_next_code_unit_sequence_length(const char *utf8_buffer, uint64_t length_left)
{
    if (length_left == 0) {
        return 0;
    }

    // We're going to assume the caller provided us with the beginning of a UTF-8 sequence.

    // Valid UTF8 has a specific binary format.
    //  If it's a single byte UTF8 character, then it is always of form '0xxxxxxx', where 'x' is any
    //  binary digit. If it's a two byte UTF8 character, then it's always of form '110xxxxx
    //  10xxxxxx'. Similarly for three and four byte UTF8 characters it starts with '1110xxxx' and
    //  '11110xxx' followed
    //      by '10xxxxxx' one less times as there are bytes.

    const auto first_byte = (uint8_t)utf8_buffer[0];
    int8_t expected_sequence_length = -1;

    // Looking for 0xxxxxxx
    // If the highest bit is 0, we know it's a single byte sequence.
    if ((first_byte & 0x80) == 0) {
        return 1;
    }

    // Looking for 110xxxxx
    // Signify a sequence of 2 bytes
    if ((first_byte >> 5) == 0x6) {
        expected_sequence_length = 2;
    }

    // Looking for 1110xxxx
    // Signify a sequence of 3 bytes
    else if ((first_byte >> 4) == 0xe) {
        expected_sequence_length = 3;
    }

    // Looking for 11110xxx
    // Signify a sequence of 4 bytes
    else if ((first_byte >> 3) == 0x1e) {
        expected_sequence_length = 4;
    }

    // If we found a valid prefix, we check that it makes sense based on the length left
    if (expected_sequence_length < 0 || ((uint64_t)expected_sequence_length) > length_left) {
        return -1;
    }

    // If it's plausible, we then check if the bytes are valid
    for (int8_t i = 1; i < expected_sequence_length; ++i) {
        // Every byte in the sequence must be prefixed by 10xxxxxx
        if ((((uint8_t)utf8_buffer[i]) >> 6) != 0x2) {
            return -1;
        }
    }

    return expected_sequence_length;
}

} // namespace

uint8_t codepoint_to_bytes(uint32_t codepoint, char *utf8_buffer)
{
    // Handle the easy case of ASCII
    if (codepoint <= 0x7F) {
        *utf8_buffer = (char)codepoint;
        return 1;
    }

    /*
     You're reading the UTF-8 encoding code, I'm sorry.
     There are multiple representations depending of the codepoint:
     0x000000-0x00007F: 0xxxxxxx
     0x000080-0x0007FF: 110xxxxx 10xxxxxx
     0x000800-0x00FFFF: 1110xxxx 10xxxxxx 10xxxxxx
     0x010000-0x10FFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
     This code could be made a bit denser but let's not look for trouble
     */

    // Out of range codepoint
    if (codepoint > UTF8_MAX_CODEPOINT) {
        return 0;
    }

    // 4 bytes representation
    if (codepoint > 0xFFFF) {
        *utf8_buffer++ = (char)(0xF0 | ((codepoint >> 18) & 0x07));
        *utf8_buffer++ = (char)(0x80 | ((codepoint >> 12) & 0x3F));
        *utf8_buffer++ = (char)(0x80 | ((codepoint >> 06) & 0x3F));
        *utf8_buffer++ = (char)(0x80 | (codepoint & 0x3F));
        return 4;
    }

    // Three bytes
    if (codepoint > 0x7FF) {
        *utf8_buffer++ = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
        *utf8_buffer++ = (char)(0x80 | ((codepoint >> 06) & 0x3F));
        *utf8_buffer++ = (char)(0x80 | (codepoint & 0x3F));
        return 3;
    }

    // Two bytes
    *utf8_buffer++ = (char)(0xC0 | ((codepoint >> 06) & 0x1F));
    *utf8_buffer++ = (char)(0x80 | (codepoint & 0x3F));
    return 2;
}

uint8_t write_codepoint(uint32_t codepoint, char *utf8_buffer, uint64_t length_left)
{
    //  If null, a surrogate or larger than the allowed range, buzz off
    if (codepoint == 0 || (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) {
        // Insert U+FFFD as an error character per-spec
        //  We need three bytes to encode it, which may be a problem as `\0` only takes two
        //  A fully correct implementation would make room for the error bytes if there isn't enough
        //  room but we won't bother with that
        if (length_left > 2) {
            // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
            *reinterpret_cast<uint8_t *>(utf8_buffer++) = 0xEFU;
            *reinterpret_cast<uint8_t *>(utf8_buffer++) = 0xBFU;
            *reinterpret_cast<uint8_t *>(utf8_buffer++) = 0xBDU;
            // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
            return 3;
        }

        return 0;
    }

    // TODO: Perform normalization

    // Insert the bytes
    return codepoint_to_bytes(codepoint, utf8_buffer);
}

uint32_t fetch_next_codepoint(const char *utf8_buffer, uint64_t &position, uint64_t length)
{
    if (position >= length) {
        return UTF8_EOF;
    }

    const int8_t next_length =
        find_next_code_unit_sequence_length(&utf8_buffer[position], length - position);
    if (next_length <= 0) {
        if (next_length == 0) {
            return UTF8_EOF;
        }
        if (next_length < 0) {
            position += 1;
            return UTF8_INVALID;
        }
    } else if (next_length == 1) {
        // Return one byte and move the position forward
        return (uint32_t)utf8_buffer[position++];
    }

    // Alright, we need to read multiple byte. The first one as a variable length so we need to deal
    // with it :( To illustrate, here is the matcher with trying to perform based on next_length
    //
    //  NGL = 2, buf = 110xxxxx -> buf & 00011111
    //  NGL = 3, buf = 1110xxxx -> buf & 00001111
    //  NGL = 4, buf = 11110xxx -> buf & 00000111
    uint32_t codepoint =
        (static_cast<uint8_t>(utf8_buffer[position])) & (0xFF >> (next_length + 1));

    // We first shift the codepoint we already loaded by 6*next_length bits to make room for
    // the 6*next_length new bits we're about to add.
    // The bytes after the header are formatted like 10xxxxxx, we thus mask by 00111111 to only
    // keep xxxxxx and append it at the end of codepoint
    if (next_length == 2) {
        codepoint <<= 6;
        codepoint |= utf8_buffer[position + 1] & 0x3F;
    } else if (next_length == 3) {
        codepoint <<= 12;
        codepoint |= (utf8_buffer[position + 1] & 0x3F) << 6;
        codepoint |= utf8_buffer[position + 2] & 0x3F;
    } else if (next_length == 4) {
        codepoint <<= 18;
        codepoint |= (utf8_buffer[position + 1] & 0x3F) << 12;
        codepoint |= (utf8_buffer[position + 2] & 0x3F) << 6;
        codepoint |= (utf8_buffer[position + 3] & 0x3F);
    }

    position += (uint8_t)next_length;
    return codepoint;
}

struct scratchpad_chunk {
    char *scratchpad;
    uint64_t length, used{0};

    explicit scratchpad_chunk(uint64_t chunk_length) : length(chunk_length)
    {
        // Allow for potential \0
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-no-malloc,hicpp-no-malloc)
        scratchpad = reinterpret_cast<char *>(malloc(length + 1));
        if (scratchpad == nullptr) {
            throw std::bad_alloc();
        }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    ~scratchpad_chunk() { free(scratchpad); }

    scratchpad_chunk(const scratchpad_chunk &) = delete;
    scratchpad_chunk(scratchpad_chunk &&chunk) noexcept
        : scratchpad(chunk.scratchpad), length(chunk.length), used(chunk.used)
    {
        chunk.scratchpad = nullptr;
    }
    scratchpad_chunk &operator=(const scratchpad_chunk &) = delete;
    scratchpad_chunk &operator=(scratchpad_chunk &&chunk) noexcept
    {
        scratchpad = chunk.scratchpad;
        length = chunk.length;
        used = chunk.used;
        chunk.scratchpad = nullptr;
        return *this;
    }
};

size_t normalize_codepoint(uint32_t codepoint, int32_t *wb_buffer, size_t wb_buffer_length)
{
    // Out of Bound
    if (codepoint >= UTF8_MAX_CODEPOINT) {
        return 0;
    }

    // ASCII or Zero-width joiner (0x200D) are used in emojis, let's keep them around
    if (codepoint <= 0x7F || codepoint == 0x200D) {
        if (wb_buffer_length > 0) {
            wb_buffer[0] = (int32_t)codepoint;
        }
        return 1;
    }

    // Hidden ASCII range (plane 14) https://en.wikipedia.org/wiki/Tags_(Unicode_block)
    // [U+E0000, U+E0019] (excluding U+E0001) has been deprecated and is unassigned
    if (codepoint == 0xE0001 || (codepoint >= 0xE0020 && codepoint <= 0xE007F)) {
        if (wb_buffer_length > 0) {
            wb_buffer[0] = static_cast<int32_t>(codepoint - 0xE0000);
        }
        return 1;
    }

    const auto decomposed_length = (size_t)utf8proc_decompose_char((int32_t)codepoint, wb_buffer,
        (utf8proc_ssize_t)wb_buffer_length,
        // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
        (utf8proc_option_t)(UTF8PROC_DECOMPOSE | UTF8PROC_IGNORE | UTF8PROC_COMPAT | UTF8PROC_LUMP |
                            UTF8PROC_STRIPMARK | UTF8PROC_STRIPNA | UTF8PROC_CASEFOLD),
        nullptr);

    // This decomposition is unfortunately not complete. It leaves behind a few chars like ı (i)
    //  Moreover, some conversions like ß (ss) require casefolding, which changes the case of
    //  characters We're trying to address what's left
    if (decomposed_length > 0 && decomposed_length <= wb_buffer_length) {
        // If casefolding happened, we check what was the case of the original codepoint and move it
        // back there This is a no-op if the case is already correct
        const utf8proc_property_t *original_codepoint_property =
            utf8proc_get_property((int32_t)codepoint);
        if (original_codepoint_property->casefold_seqindex != UINT16_MAX) {
            if ((original_codepoint_property->category &
                    (UTF8PROC_CATEGORY_LU | UTF8PROC_CATEGORY_LL)) != 0) {
                const bool original_cp_was_upper =
                    original_codepoint_property->category == UTF8PROC_CATEGORY_LU;
                for (size_t wb_index = 0; wb_index < decomposed_length; ++wb_index) {
                    if (original_cp_was_upper) {
                        wb_buffer[wb_index] = utf8proc_toupper(wb_buffer[wb_index]);
                    } else {
                        wb_buffer[wb_index] = utf8proc_tolower(wb_buffer[wb_index]);
                    }
                }
            } else {
                // We're forcing a case conversion back and forth if necessary to catch the few
                // stragglers like ı (i)
                for (size_t wb_index = 0; wb_index < decomposed_length; ++wb_index) {
                    const utf8proc_property_t *codepoint_property =
                        utf8proc_get_property(wb_buffer[wb_index]);

                    // If this is a uppercase codepoint, we do a tolower then toupper
                    if (codepoint_property->category == UTF8PROC_CATEGORY_LU) {
                        wb_buffer[wb_index] =
                            utf8proc_toupper(utf8proc_tolower(wb_buffer[wb_index]));
                    }

                    // If this is a lowercase codepoint, we do a toupper then tolower
                    else if (codepoint_property->category == UTF8PROC_CATEGORY_LL) {
                        wb_buffer[wb_index] =
                            utf8proc_tolower(utf8proc_toupper(wb_buffer[wb_index]));
                    }
                }
            }
        }
    }

    return decomposed_length;
}

// We empirically measured that no codepoint decomposition exceeded 18 codepoints.
bool normalize_string(cow_string &str)
{
    try {
        static constexpr std::size_t inflight_buffer_size = 24;

        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        int32_t in_flight_buffer[inflight_buffer_size];
        std::vector<scratchpad_chunk> scratch_pad;

        // A tricky part of this conversion is that the output size is totally unknown, but we want
        // to be efficient with our allocations. We're going to write the glyph we're normalising in
        // a static buffer (if possible) and write the filtered, normalized results in a bunch of
        // semi-fixed buffer (the scratchpad) Only when the conversion is over will we allocate the
        // final buffer and copy everything in there.
        scratch_pad.reserve(8);
        scratch_pad.emplace_back(str.length() > 1024 ? str.length() : 1024);

        uint32_t codepoint;
        uint64_t position = 0;
        while ((codepoint = fetch_next_codepoint(str.data(), position, str.length())) != UTF8_EOF) {
            // Ignore invalid glyphs
            if (codepoint == UTF8_INVALID) {
                continue;
            }

            const size_t decomposed_length =
                normalize_codepoint(codepoint, in_flight_buffer, inflight_buffer_size);

            // No codepoint can generate more than 18 codepoints, that's extremely odd
            //  Let's drop this codepoint
            if (decomposed_length > inflight_buffer_size) {
                continue;
            }

            // Write the codepoints to the scratchpad
            for (size_t inflight_buffer_index = 0; inflight_buffer_index < decomposed_length;
                 ++inflight_buffer_index) {
                // NOLINTNEXTLINE(modernize-avoid-c-arrays)
                char utf8_write[4];
                const uint8_t length_written = write_codepoint(
                    (uint32_t)in_flight_buffer[inflight_buffer_index], utf8_write, 4);

                if (scratch_pad.back().used + length_written >= scratch_pad.back().length) {
                    scratch_pad.emplace_back(scratch_pad.back().length);
                }

                scratchpad_chunk &last = scratch_pad.back();
                memcpy(&last.scratchpad[last.used], utf8_write, length_written);
                last.used += length_written;
            }
        }

        std::size_t new_length = 0;
        char *new_buffer = nullptr;
        if (scratch_pad.size() == 1) {
            // We have a single scratchpad, we can simply swap the pointers :D
            new_buffer = scratch_pad.front().scratchpad;
            new_length = scratch_pad.front().used;
            // Prevent the destructor from freeing the pointer we're now using.
            scratch_pad.front().scratchpad = nullptr;
        } else {
            // Compile the scratch pads into the final normalized string
            for (const scratchpad_chunk &chunk : scratch_pad) { new_length += chunk.used; }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-no-malloc,hicpp-no-malloc)
            new_buffer = reinterpret_cast<char *>(malloc(new_length + 1));
            if (new_buffer == nullptr) {
                return false;
            }

            uint64_t write_index = 0;
            for (const scratchpad_chunk &chunk : scratch_pad) {
                memcpy(&new_buffer[write_index], chunk.scratchpad, chunk.used);
                write_index += chunk.used;
            }
        }

        new_buffer[new_length] = '\0';
        str.replace_buffer(new_buffer, new_length);

        return true;
    } catch (const std::bad_alloc & /*unused*/) {} // NOLINT(bugprone-empty-catch)

    return false;
}

} // namespace ddwaf::utf8
