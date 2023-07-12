// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "transformer/utf8.hpp"
#include "utils.hpp"

extern "C" {
#include <stdint.h>
#define UTF8PROC_STATIC
#include <utf8proc.h>
}

namespace ddwaf::utf8 {

uint8_t codepoint_to_bytes(uint32_t codepoint, char *utf8Buffer)
{
    // Handle the easy case of ASCII
    if (codepoint <= 0x7F) {
        *utf8Buffer = (char)codepoint;
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
    if (codepoint > UTF8_MAX_CODEPOINT)
        return 0;

    // 4 bytes representation
    if (codepoint > 0xFFFF) {
        *utf8Buffer++ = (char)(0xF0 | ((codepoint >> 18) & 0x07));
        *utf8Buffer++ = (char)(0x80 | ((codepoint >> 12) & 0x3F));
        *utf8Buffer++ = (char)(0x80 | ((codepoint >> 06) & 0x3F));
        *utf8Buffer++ = (char)(0x80 | (codepoint & 0x3F));
        return 4;
    }
    // Three bytes
    else if (codepoint > 0x7FF) {
        *utf8Buffer++ = (char)(0xE0 | ((codepoint >> 12) & 0x0F));
        *utf8Buffer++ = (char)(0x80 | ((codepoint >> 06) & 0x3F));
        *utf8Buffer++ = (char)(0x80 | (codepoint & 0x3F));
        return 3;
    }
    // Two bytes
    else {
        *utf8Buffer++ = (char)(0xC0 | ((codepoint >> 06) & 0x1F));
        *utf8Buffer++ = (char)(0x80 | (codepoint & 0x3F));
        return 2;
    }
}

uint8_t write_codepoint(uint32_t codepoint, char *utf8Buffer, uint64_t lengthLeft)
{
    //  If null, a surrogate or larger than the allowed range, buzz off
    if (codepoint == 0 || (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) {
        // Insert U+FFFD as an error character per-spec
        //  We need three bytes to encode it, which may be a problem as `\0` only takes two
        //  A fully correct implementation would make room for the error bytes if there isn't enough
        //  room but we won't bother with that
        if (lengthLeft > 2) {
            *((uint8_t *)utf8Buffer++) = 0xEFu;
            *((uint8_t *)utf8Buffer++) = 0xBFu;
            *((uint8_t *)utf8Buffer++) = 0xBDu;
            return 3;
        }

        return 0;
    }

    // TODO: Perform normalization

    // Insert the bytes
    return codepoint_to_bytes(codepoint, utf8Buffer);
}

int8_t findNextGlyphLength(const char *utf8Buffer, uint64_t lengthLeft)
{
    if (lengthLeft == 0) {
        return 0;
    }

    // We're going to assume the caller provided us with the beginning of a UTF-8 sequence.

    // Valid UTF8 has a specific binary format.
    //  If it's a single byte UTF8 character, then it is always of form '0xxxxxxx', where 'x' is any
    //  binary digit. If it's a two byte UTF8 character, then it's always of form '110xxxxx
    //  10xxxxxx'. Similarly for three and four byte UTF8 characters it starts with '1110xxxx' and
    //  '11110xxx' followed
    //      by '10xxxxxx' one less times as there are bytes.

    uint8_t firstByte = (uint8_t)utf8Buffer[0];
    int8_t expectedSequenceLength = -1;

    // Looking for 0xxxxxxx
    // Of the highest bit is 0, we know it's a single bit sequence.
    if ((firstByte & 0x80) == 0) {
        return 1;
    }

    // Looking for 110xxxxx
    // Signify a sequence of 2 bytes
    if ((firstByte >> 5) == 0x6) {
        expectedSequenceLength = 2;
    }

    // Looking for 1110xxxx
    // Signify a sequence of 3 bytes
    else if ((firstByte >> 4) == 0xe) {
        expectedSequenceLength = 3;
    }

    // Looking for 11110xxx
    // Signify a sequence of 4 bytes
    else if ((firstByte >> 3) == 0x1e) {
        expectedSequenceLength = 4;
    }

    // If we found a valid prefix, we check that it makes sense based on the length left
    if (expectedSequenceLength < 0 || ((uint64_t)expectedSequenceLength) > lengthLeft) {
        return -1;
    }

    // If it's plausible, we then check if the bytes are valid
    for (int8_t i = 1; i < expectedSequenceLength; ++i) {
        // Every byte in the sequence must be prefixed by 10xxxxxx
        if ((((uint8_t)utf8Buffer[i]) >> 6) != 0x2) {
            return -1;
        }
    }

    return expectedSequenceLength;
}

uint32_t fetch_next_codepoint(const char *utf8Buffer, uint64_t &position, uint64_t length)
{
    if (position > length) {
        return UTF8_INVALID;
    }

    int8_t nextGlyphLength = findNextGlyphLength(&utf8Buffer[position], length - position);
    if (nextGlyphLength <= 0) {
        if (nextGlyphLength == 0) {
            return UTF8_EOF;
        } else if (nextGlyphLength < 0) {
            position += 1;
            return UTF8_INVALID;
        }
    } else if (nextGlyphLength == 1) {
        // Return one byte and move the position forward
        return (uint32_t)utf8Buffer[position++];
    }

    // Alright, we need to read multiple byte. The first one as a variable length so we need to deal
    // with it :( To illustrate, here is the operation with trying to perform based on
    // nextGlyphLength
    //
    //  NGL = 2, buf = 110xxxxx -> buf & 00011111
    //  NGL = 3, buf = 1110xxxx -> buf & 00001111
    //  NGL = 4, buf = 11110xxx -> buf & 00000111

    uint32_t codepoint = ((uint8_t)utf8Buffer[position]) & (0xFF >> (nextGlyphLength + 1));

    // Once we parsed the header, we parse the following bytes
    for (uint8_t byteIndex = 1; byteIndex < nextGlyphLength; ++byteIndex) {
        // We first shift the codepoint we already loaded by 6 bits to make room for the 6 new bits
        // we're about to add
        codepoint <<= 6;

        // The bytes after the header are formatted like 10xxxxxx, we thus mask by 00111111 to only
        // keep xxxxxx and append it at the end of codepoint
        codepoint |= utf8Buffer[position + byteIndex] & 0x3F;
    }

    position += (uint8_t)nextGlyphLength;
    return codepoint;
}

struct ScratchpadChunck {
    char *scratchpad;
    uint64_t length, used;

    ScratchpadChunck(uint64_t chunckLength) : length(chunckLength), used(0)
    {
        // Allow for potential \0
        scratchpad = (char *)malloc(length + 1);
    }

    ScratchpadChunck(ScratchpadChunck &) = delete;
    ScratchpadChunck(ScratchpadChunck &&chunck)
        : scratchpad(chunck.scratchpad), length(chunck.length), used(chunck.used)
    {
        chunck.scratchpad = nullptr;
    }

    ~ScratchpadChunck() { free(scratchpad); }
};

size_t normalize_codepoint(uint32_t codepoint, int32_t *wbBuffer, size_t wbBufferLength)
{
    // Out of Bound
    if (codepoint >= UTF8_MAX_CODEPOINT) {
        return 0;
    }

    // ASCII or Zero-width joiner (0x200D) are used in emojis, let's keep them around
    else if (codepoint <= 0x7F || codepoint == 0x200D) {
        if (wbBufferLength > 0) {
            wbBuffer[0] = (int32_t)codepoint;
        }
        return 1;
    }

    size_t decomposedLength = (size_t)utf8proc_decompose_char((int32_t)codepoint, wbBuffer,
        (utf8proc_ssize_t)wbBufferLength,
        (utf8proc_option_t)(UTF8PROC_DECOMPOSE | UTF8PROC_IGNORE | UTF8PROC_COMPAT | UTF8PROC_LUMP |
                            UTF8PROC_STRIPMARK | UTF8PROC_STRIPNA | UTF8PROC_CASEFOLD),
        nullptr);

    // This decomposition is unfortunately not complete. It leaves behind a few chars like Ä± (i)
    //  Moreover, some conversions like Ã (ss) require casefolding, which changes the case of
    //  characters We're trying to address what's left
    if (decomposedLength > 0 && decomposedLength <= wbBufferLength) {
        // If casefolding happened, we check what was the case of the original codepoint and move it
        // back there This is a no-op if the case is already correct
        const utf8proc_property_t *originalCodepointProperty =
            utf8proc_get_property((int32_t)codepoint);
        if (originalCodepointProperty->casefold_seqindex != UINT16_MAX) {
            if (originalCodepointProperty->category &
                (UTF8PROC_CATEGORY_LU | UTF8PROC_CATEGORY_LL)) {
                bool originalCPWasUpper =
                    originalCodepointProperty->category == UTF8PROC_CATEGORY_LU;
                for (size_t wbIndex = 0; wbIndex < decomposedLength; ++wbIndex) {
                    if (originalCPWasUpper) {
                        wbBuffer[wbIndex] = utf8proc_toupper(wbBuffer[wbIndex]);
                    } else {
                        wbBuffer[wbIndex] = utf8proc_tolower(wbBuffer[wbIndex]);
                    }
                }
            }
        } else {
            // We're forcing a case conversion back and forth if necessary to catch the few
            // stragglers like Ä± (i)
            for (size_t wbIndex = 0; wbIndex < decomposedLength; ++wbIndex) {
                const utf8proc_property_t *codepointProperty =
                    utf8proc_get_property(wbBuffer[wbIndex]);

                // If this is a uppercase codepoint, we do a tolower then toupper
                if (codepointProperty->category == UTF8PROC_CATEGORY_LU) {
                    wbBuffer[wbIndex] = utf8proc_toupper(utf8proc_tolower(wbBuffer[wbIndex]));
                }

                // If this is a lowercase codepoint, we do a toupper then tolower
                else if (codepointProperty->category == UTF8PROC_CATEGORY_LL) {
                    wbBuffer[wbIndex] = utf8proc_tolower(utf8proc_toupper(wbBuffer[wbIndex]));
                }
            }
        }
    }

    return decomposedLength;
}

// We empirically measured that no codepoint decomposition exceeded 18 codepoints.
#define INFLIGHT_BUFFER_SIZE 24

bool normalize_string(char **_utf8Buffer, uint64_t &bufferLength)
{
    const char *utf8Buffer = *_utf8Buffer;
    int32_t inFlightBuffer[INFLIGHT_BUFFER_SIZE];
    std::vector<ScratchpadChunck> scratchPad;

    // A tricky part of this conversion is that the output size is totally unknown, but we want to
    // be efficient with our allocations. We're going to write the glyph we're normalising in a
    // static buffer (if possible) and write the filtered, normalized results in a bunch of
    // semi-fixed buffer (the scratchpad) Only when the conversion is over will we allocate the
    // final buffer and copy everything in there.
    scratchPad.reserve(8);
    scratchPad.emplace_back(bufferLength > 1024 ? bufferLength : 1024);

    uint32_t codepoint;
    uint64_t position = 0;
    while ((codepoint = fetch_next_codepoint(utf8Buffer, position, bufferLength)) != UTF8_EOF) {
        // Ignore invalid glyphs
        if (codepoint == UTF8_INVALID) {
            continue;
        }

        size_t decomposedLength =
            normalize_codepoint(codepoint, inFlightBuffer, INFLIGHT_BUFFER_SIZE);

        // No codepoint can generate more than 18 codepoints, that's extremely odd
        //  Let's drop this codepoint
        if (decomposedLength > INFLIGHT_BUFFER_SIZE) {
            continue;
        }

        // Write the codepoints to the scratchpad
        for (size_t inflightBufferIndex = 0; inflightBufferIndex < decomposedLength;
             ++inflightBufferIndex) {
            char utf8Write[4];
            uint8_t lengthWritten =
                write_codepoint((uint32_t)inFlightBuffer[inflightBufferIndex], utf8Write, 4);

            if (scratchPad.back().used + lengthWritten >= scratchPad.back().length) {
                scratchPad.emplace_back(scratchPad.back().length);
            }

            ScratchpadChunck &last = scratchPad.back();
            memcpy(&last.scratchpad[last.used], utf8Write, lengthWritten);
            last.used += lengthWritten;
        }
    }

    if (scratchPad.size() == 1) {
        // We have a single scratchpad, we can simply swap the pointers :D
        free(*_utf8Buffer);
        *_utf8Buffer = scratchPad.front().scratchpad;
        bufferLength = scratchPad.front().used;

        // Prevent the destructor from freeing the pointer we're now using.
        scratchPad.front().scratchpad = nullptr;
    } else {
        // Compile the scratch pads into the final normalized string
        uint64_t outputLength = 0;
        for (ScratchpadChunck &chunck : scratchPad) { outputLength += chunck.used; }

        if (outputLength > bufferLength) {
            void *newUTF8Buffer = realloc((void *)*_utf8Buffer, outputLength);
            if (newUTF8Buffer == nullptr) {
                return false;
            }
            *_utf8Buffer = (char *)newUTF8Buffer;
        }

        uint64_t writeIndex = 0;
        for (ScratchpadChunck &chunck : scratchPad) {
            memcpy(&(*_utf8Buffer)[writeIndex], chunck.scratchpad, chunck.used);
            writeIndex += chunck.used;
        }

        bufferLength = writeIndex;
    }

    return true;
}

bool normalize_string(lazy_string &str)
{
    int32_t inFlightBuffer[INFLIGHT_BUFFER_SIZE];
    std::vector<ScratchpadChunck> scratchPad;

    // A tricky part of this conversion is that the output size is totally unknown, but we want to
    // be efficient with our allocations. We're going to write the glyph we're normalising in a
    // static buffer (if possible) and write the filtered, normalized results in a bunch of
    // semi-fixed buffer (the scratchpad) Only when the conversion is over will we allocate the
    // final buffer and copy everything in there.
    scratchPad.reserve(8);
    scratchPad.emplace_back(str.length() > 1024 ? str.length() : 1024);

    uint32_t codepoint;
    uint64_t position = 0;
    while ((codepoint = fetch_next_codepoint(str.data(), position, str.length())) != UTF8_EOF) {
        // Ignore invalid glyphs
        if (codepoint == UTF8_INVALID) {
            continue;
        }

        size_t decomposedLength =
            normalize_codepoint(codepoint, inFlightBuffer, INFLIGHT_BUFFER_SIZE);

        // No codepoint can generate more than 18 codepoints, that's extremely odd
        //  Let's drop this codepoint
        if (decomposedLength > INFLIGHT_BUFFER_SIZE) {
            continue;
        }

        // Write the codepoints to the scratchpad
        for (size_t inflightBufferIndex = 0; inflightBufferIndex < decomposedLength;
             ++inflightBufferIndex) {
            char utf8Write[4];
            uint8_t lengthWritten =
                write_codepoint((uint32_t)inFlightBuffer[inflightBufferIndex], utf8Write, 4);

            if (scratchPad.back().used + lengthWritten >= scratchPad.back().length) {
                scratchPad.emplace_back(scratchPad.back().length);
            }

            ScratchpadChunck &last = scratchPad.back();
            memcpy(&last.scratchpad[last.used], utf8Write, lengthWritten);
            last.used += lengthWritten;
        }
    }

    std::size_t new_length = 0;
    char *new_buffer = nullptr;
    if (scratchPad.size() == 1) {
        // We have a single scratchpad, we can simply swap the pointers :D
        new_buffer = scratchPad.front().scratchpad;
        new_length = scratchPad.front().used;
        // Prevent the destructor from freeing the pointer we're now using.
        scratchPad.front().scratchpad = nullptr;
    } else {
        // Compile the scratch pads into the final normalized string
        for (ScratchpadChunck &chunck : scratchPad) { new_length += chunck.used; }

        new_buffer = (char *)malloc(new_length + 1);
        if (new_buffer == nullptr) {
            return false;
        }

        uint64_t writeIndex = 0;
        for (ScratchpadChunck &chunck : scratchPad) {
            memcpy(&new_buffer[writeIndex], chunck.scratchpad, chunck.used);
            writeIndex += chunck.used;
        }
    }

    new_buffer[new_length] = '\0';
    str.reset(new_buffer, new_length);

    return true;
}

} // namespace ddwaf::utf8
