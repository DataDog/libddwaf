// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include <PWTransformer.h>

#include <utf8.hpp>
#include <utils.h>

static uint8_t fromHex(char c);
static bool replaceIfMatch(char *array, uint64_t &readHead, uint64_t &writeHead,
    uint64_t readLengthLeft, const char *token, uint32_t tokenLength, char decodedToken);
static bool decodeBase64(char *array, uint64_t &length);

bool PWTransformer::runTransform(
    ddwaf_object *parameter, const std::function<transformer> &transformer, bool readOnly)
{
    if (parameter->type != DDWAF_OBJ_STRING || parameter->stringValue == NULL)
        return false;

    uint64_t newLength = parameter->nbEntries;
    bool success = transformer((char *)parameter->stringValue, newLength, readOnly);

    if (!readOnly)
        parameter->nbEntries = newLength;

    return success;
}

bool PWTransformer::transformLowerCase(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            size_t pos = 0;

            // First loop looking for the first non-lowercase char
            for (; pos < length && (array[pos] < 'A' || array[pos] > 'Z'); ++pos) {}

            //  If we're checking whether we need to do change, finding such a char mean we need to
            //  do so (we return true if we need to update)
            if (readOnly)
                return pos != length;

            //  If we're mutating the string, then we have the starting offset
            for (; pos < length; ++pos) {
                if (array[pos] >= 'A' && array[pos] <= 'Z')
                    array[pos] += 'a' - 'A';
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformNoNull(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            // First loop looking for the first null char
            uint64_t read = 0;
            for (; read < length && array[read]; ++read) {}

            //  If we're checking whether we need to do change, finding such a char mean we need to
            //  do so (we return true if we need to update)
            if (readOnly)
                return read != length;

            //  If we're mutating the string, then we have the starting offset
            uint64_t write = read;
            for (; read < length; ++read) {
                if (!array[read])
                    continue;

                array[write++] = array[read];
            }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformCompressWhiteSpace(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            // First loop looking for the first two consecutives space char
            uint64_t read = 1;
            for (; read < length && (array[read] != ' ' || array[read - 1] != ' '); ++read) {}

            //  If we're checking whether we need to do change, finding such a chain mean we need to
            //  do so (we return true if we need to update)
            if (readOnly)
                return read < length;

            //  If we're mutating the string, then we have the starting offset
            uint64_t write = read;
            while (read < length) {
                // When we find two consecutive spaces, we skip over them
                //  We check with read - 1 to make sure at least one space is commited
                if (array[read] == ' ' && array[read - 1] == ' ') {
                    // Skip ahead
                    while (++read < length && array[read] == ' ') {}

                    // Should we run the end of the loop?
                    if (read == length)
                        break;
                }

                array[write++] = array[read++];
            }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformLength(ddwaf_object *parameter, bool readOnly)
{
    if (parameter->type != DDWAF_OBJ_STRING)
        return false;

    // We simply convert the string into a ddwaf_object with its length
    if (!readOnly) {
        const uint64_t length = parameter->nbEntries;
        ddwaf_object_free(parameter);
        ddwaf_object_unsigned_force(parameter, length);
    }

    return true;
}

/**
 transformNormalize: normalize Unix path
 This transformer simplify relative paths and remove self references
 */
bool PWTransformer::transformNormalize(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            uint64_t read = 0, write = 0;

            // Our algorithm is quite simple: we look for `./`. If we find that, we check if the
            // preceeding char is:
            //  - `/` (and thus skip the `./`)
            //  - `/.` and we thus erase the last directory
            while (read < length) {
                // Everything is cool, writing away
                if (array[read] != '.' || (read + 1 != length && array[read + 1] != '/')) {
                    array[write++] = array[read++];
                    continue;
                }

                // We handle both the `./script` and `bla/./bla` here by ignoring the next two
                // characters
                if (read == 0 || array[read - 1] == '/') {
                    if (readOnly)
                        return true;

                    read += 2;
                }

                // We handle /../ by moving the write head back to the previous `/`
                else if (read > 1 && array[read - 1] == '.' && array[read - 2] == '/') {
                    if (readOnly)
                        return true;

                    // The write head already wrote /., we need to move it back by three
                    //  MIN make sure we can't underflow although I don't really see how that could
                    //  happen
                    write -= std::min(write, (uint64_t)3);

                    while (write != 0 && array[write] != '/') { write -= 1; }

                    // Move forward the read head, and add back the / to the write head
                    array[write++] = '/';
                    read += 2;
                }

                // nvm, false alarm, just a dir ending with .
                else {
                    array[write++] = array[read++];
                }
            }

            if (readOnly)
                return false;

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

/**
 transformNormalizeWin: normalize Windows path
 This transformer first convert any \ into /, then run the standard normalization as described above
 */
bool PWTransformer::transformNormalizeWin(ddwaf_object *parameter, bool readOnly)
{
    // This sanitization is usually handled by runTransform but we want to chain two transforms here
    if (parameter->type != DDWAF_OBJ_STRING || parameter->stringValue == NULL)
        return false;

    // Look for any backslash
    uint64_t pos = 0;
    for (; pos < parameter->nbEntries && parameter->stringValue[pos] != '\\'; ++pos) {}

    // If it found one, then that mean we will need to transform this string
    if (pos < parameter->nbEntries) {
        if (readOnly)
            return true;

        // That's quite a blunt conversion but that's what ModSecurity is doing so ¯\_(ツ)_/¯
        //  https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/actions/transformations/normalise_path.cc#L64
        do {
            if (parameter->stringValue[pos] == '\\')
                ((char *)parameter->stringValue)[pos] = '/';

        } while (++pos < parameter->nbEntries);
    }

    // TODO: Should save the drive letter so that `C:/../` properly result in `C:/`

    // Run the Unix normalization
    return transformNormalize(parameter, readOnly);
}

bool PWTransformer::transformDecodeURL(ddwaf_object *parameter, bool readOnly, bool readIIS)
{
    /*
     * ModSecurity's documentation is atrocious and the code isn't much better
     * Bypasses are very helpfully documented here:
     * https://www.postexplo.com/forum/ids-ips/network-based/764-ids-evasion-techniques-using-url-encoding
     */
    return runTransform(
        parameter,
        [readIIS](char *array, uint64_t &length, bool readOnly) -> bool {
            uint64_t read = 0;

            // Fast forward to a space or an hex encode char
            for (; read < length && array[read] != '+'; ++read) {
                // Is there an hex encoded char?
                if (read + 2 < length && array[read] == '%' && isxdigit(array[read + 1]) &&
                    isxdigit(array[read + 2]))
                    break;

                if (readIIS && read + 5 < length && array[read] == '%' &&
                    (array[read + 1] | 0x20) == 'u' && isxdigit(array[read + 2]) &&
                    isxdigit(array[read + 3]) && isxdigit(array[read + 4]) &&
                    isxdigit(array[read + 5])) {
                    break;
                }
            }

            if (readOnly)
                return read != length;

            uint64_t write = read;

            while (read < length) {
                if (array[read] == '+') {
                    array[write++] = ' ';
                    read += 1;
                } else if (array[read] == '%') {
                    // Normal URL encoding
                    if (read + 2 < length && isxdigit(array[read + 1]) &&
                        isxdigit(array[read + 2])) {
                        // TODO: we'll need to perform normalization here too
                        const uint8_t highBits = fromHex(array[read + 1]);
                        const uint8_t lowBits = fromHex(array[read + 2]);
                        array[write++] = (char)(highBits << 4u | lowBits);
                        read += 3;
                    }
                    // IIS-encoded wide characters
                    else if (readIIS && read + 5 < length && (array[read + 1] | 0x20) == 'u' &&
                             isxdigit(array[read + 2]) && isxdigit(array[read + 3]) &&
                             isxdigit(array[read + 4]) && isxdigit(array[read + 5])) {
                        // Rebuild the codepoint from the hex
                        const uint16_t codepoint =
                            (uint16_t)(fromHex(array[read + 2]) << 12u |
                                       fromHex(array[read + 3]) << 8u |
                                       fromHex(array[read + 4]) << 4u | fromHex(array[read + 5]));

                        read += 6;

                        if (codepoint <= 0x7f) {
                            array[write++] = (char)codepoint;
                        } else {
                            write += ddwaf::utf8::write_codepoint(
                                codepoint, &array[write], read - write);
                        }
                    }
                    // Fallback
                    else {
                        array[write++] = array[read++];
                    }
                } else {
                    array[write++] = array[read++];
                }
            }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformDecodeCSS(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            uint64_t read = 0;

            // As soon as we find a backslash, we know the string will need to change somehow
            for (; read < length && array[read] != '\\'; ++read) {}

            if (readOnly)
                return read != length;

            uint64_t write = read;

            // Encoding specification: https://drafts.csswg.org/css-syntax/#escape-codepoint
            while (read < length) {
                if (array[read] != '\\') {
                    array[write++] = array[read++];
                    continue;
                }

                read += 1;

                // Count the number of hex characters following the \, with a maximum of 6
                uint8_t countHex = 0;
                while (
                    countHex < 6 && read + countHex < length && isxdigit(array[read + countHex])) {
                    countHex += 1;
                }

                // We need to decode
                if (countHex) {
                    // Turn the hex sequence into an uint32_t
                    uint32_t assembledValue = 0;
                    for (uint8_t count = countHex; count != 0; --count) {
                        assembledValue <<= 4;
                        assembledValue |= fromHex(array[read++]);
                    }

                    // Process the codepoint:
                    // https://drafts.csswg.org/css-syntax/#consume-escaped-code-point
                    write +=
                        ddwaf::utf8::write_codepoint(assembledValue, &array[write], read - write);

                    // If a whitespace follow an escape, it's swallowed
                    if (read < length && isspace(array[read]))
                        read += 1;
                }
                // Simple escape
                else if (read < length) {
                    // A \n following a \\ is ignored
                    const char nextChar = array[read++];
                    if (nextChar != '\n')
                        array[write++] = nextChar;
                }
            }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformDecodeJS(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            uint64_t read = 0;

            // As soon as we find a backslash, we know the string will need to change somehow
            for (; read < length && array[read] != '\\'; ++read) {}

            if (readOnly)
                return read + 1 < length;

            uint64_t write = read;
            // There are three kinds of escape in JS:
            //   \X where X is an ASCII character (\n...) Can also escape normal ASCII characters
            //   \xYY where YY are one hex-encoded byte
            //   \uZZZZ where ZZZZ are a UTF-16 representation in hex, which we need to convert to
            //   UTF-8

            while (read < length) {
                if (array[read] != '\\') {
                    array[write++] = array[read++];
                    continue;
                }

                // Move past the backslash
                if (++read == length) {
                    array[write++] = '\\';
                    continue;
                }

                const char escapeControl = array[read++];

                // Hex sequence, we're fairly permissive and invalid hex sequences are simply
                // ignored
                if (escapeControl == 'x') {
                    if (read + 1 < length && isxdigit(array[read]) && isxdigit(array[read + 1])) {
                        array[write++] =
                            (char)(fromHex(array[read]) << 4 | fromHex(array[read + 1]));
                        read += 2;
                    }
                }
                // UTF-16 :(
                // Convert UTF-16-BE to UTF-8
                else if (escapeControl == 'u') {
                    // Check that the next four bytes are hex
                    if (read + 3 < length && isxdigit(array[read]) && isxdigit(array[read + 1]) &&
                        isxdigit(array[read + 2]) && isxdigit(array[read + 3])) {
                        // Assume UTF-16 big endian as this is what Node is giving me
                        const uint16_t word =
                            (uint16_t)(fromHex(array[read]) << 12 | fromHex(array[read + 1]) << 8 |
                                       fromHex(array[read + 2]) << 4 | fromHex(array[read + 3]));
                        read += 4;

                        // The word is a codepoint
                        if (word < 0xd800 || word > 0xdbff) {
                            write += ddwaf::utf8::codepoint_to_bytes(word, &array[write]);
                        }
                        // The word is a surrogate, lets see if the other half is there
                        else if (read + 5 < length && array[read] == '\\' &&
                                 array[read + 1] == 'u' && isxdigit(array[read + 2]) &&
                                 isxdigit(array[read + 3]) && isxdigit(array[read + 4]) &&
                                 isxdigit(array[read + 5])) {
                            const uint16_t lowSurrogate =
                                (uint16_t)(fromHex(array[read + 2]) << 12 |
                                           fromHex(array[read + 3]) << 8 |
                                           fromHex(array[read + 4]) << 4 |
                                           fromHex(array[read + 5]));

                            // Correct surrogate sequence?
                            if (lowSurrogate >= 0xdc00 && lowSurrogate <= 0xdfff) {
                                // Good, now let's rebuild the codepoint
                                // Implementing the algorithm from
                                // https://en.wikipedia.org/wiki/UTF-16#Examples
                                uint32_t codepoint =
                                    0x10000u + ((word - 0xd800u) << 10u) + (lowSurrogate - 0xdc00u);
                                write += ddwaf::utf8::codepoint_to_bytes(codepoint, &array[write]);
                                read += 6;
                            }

                            // If it's wrong, let's ignore the first surrogate, and act as if we
                            // didn't see the second codepoint. THe next iteration will take care of
                            // it
                        } else {
                            // Tried to make us write a half surrogate, write the error bytes
                            write +=
                                ddwaf::utf8::write_codepoint(word, &array[write], read - write);
                        }
                    }
                }
                // Escaped char
                else {
                    char character = escapeControl;

                    // We only check for cases where the next character isn't simply escaped. For
                    // this case, copying the unmodified `character` is enough
                    switch (character) {
                    case 'a':
                        character = '\a';
                        break;

                    case 'b':
                        character = '\b';
                        break;

                    case 'f':
                        character = '\f';
                        break;

                    case 'n':
                        character = '\n';
                        break;

                    case 'r':
                        character = '\r';
                        break;

                    case 't':
                        character = '\t';
                        break;

                    case 'v':
                        character = '\v';
                        break;
                    }

                    array[write++] = character;
                }
            }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformDecodeHTML(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            // If the string is too short
            if (length < 3)
                return readOnly ? 0 : length;

            uint64_t read = 0;

            // There are three kinds of escape in HTML:
            //   &#XXXXX; where XX are numerical digits
            //   &#xYYY; or &#XYYY; where YYY is an hex-encoded codepoint
            //   &ZZZZ; where ZZZZ is an alphanumerical name for the character
            //  In practice, the semicolon is optional

            if (readOnly) {
                // We're doing a quick sweep for the codepoints tags. They're easier to detect than
                // character references This also let us avoid cluttering the main codepath
                for (; read < length - 2; ++read) {
                    if (array[read] == '&' && array[read + 1] == '#') {
                        if (array[read + 2] == 'x' || array[read + 2] == 'X') {
                            if (read + 3 < length && isxdigit(array[read + 3])) {
                                return true;
                            }

                            read += 1;
                        } else if (isdigit(array[read + 2])) {
                            return true;
                        }

                        read += 2;
                    }
                }
            }

            // We skip ahead looking for a `&`. That's not enough to know for sure if we need to
            // edit but it's a decent shortcut nonetheless
            for (read = 0; read < length && array[read] != '&'; ++read)
                ;

            uint64_t write = read;

            while (read < length) {
                if (array[read] != '&' || read == length - 1) {
                    array[write++] = array[read++];
                    continue;
                }

                read += 1; // Skip the &
                // Codepoint
                if (array[read] == '#') {
                    read += 1; // Skip the #

                    uint32_t codePoint = 0;

                    // Hexadecimal codepoint
                    if (read < length - 1 && (array[read] == 'x' || array[read] == 'X') &&
                        isxdigit(array[read + 1])) {
                        read += 1; // Skip the x

                        // Compute the codepoint. We need to compute an arbitrary number of hex
                        // chars because browsers do too :(
                        while (read < length && isxdigit(array[read])) {
                            codePoint <<= 4;
                            codePoint |= fromHex(array[read++]);

                            // If we go out of range, move the read head to the end and abort
                            // immediately. We don't want to risk an overflow
                            if (codePoint > 0x10ffff) {
                                for (; read < length && isxdigit(array[read]); read += 1) {}
                            }
                        }
                    }
                    // Numeric codepoint
                    else if (read < length && isdigit(array[read])) {
                        // Compute the codepoint. We need to compute an arbitrary number of digits
                        // because browsers do too :(
                        while (read < length && isdigit(array[read])) {
                            codePoint *= 10;
                            codePoint += (uint32_t)array[read++] - '0';

                            // If we go out of range, move the read head to the end and abort
                            // immediately. We don't want to risk an overflow
                            if (codePoint > 0x10ffff) {
                                for (; read < length && isdigit(array[read]); read += 1) {}
                            }
                        }
                    }
                    // Accidental match
                    else {
                        array[write++] = '&';
                        array[write++] = '#';
                        continue;
                    }

                    // We extracted the codepoint (or bailed out). Now, we can transcribe it
                    write += ddwaf::utf8::write_codepoint(codePoint, &array[write], read - write);

                    if (read < length && array[read] == ';')
                        read += 1;
                }
                // Named character references
                else if (isalnum(array[read])) {
                    const uint64_t lengthLeft = length - read;
                    const char oldWriteChar = array[write];

                    // Try to decode a few known references
                    if (!replaceIfMatch(array, read, write, lengthLeft, "lt;", 3, '<') &&
                        !replaceIfMatch(array, read, write, lengthLeft, "gt;", 3, '>') &&
                        !replaceIfMatch(array, read, write, lengthLeft, "amp;", 4, '&') &&
                        !replaceIfMatch(array, read, write, lengthLeft, "quot;", 5, '"') &&
                        !replaceIfMatch(array, read, write, lengthLeft, "nbsp;", 5, (char)160)) {
                        // If none work, write the & we skipped
                        array[write++] = '&';
                    }
                    // If this is a read only check, we covered the codepoint path but not this one!
                    else if (readOnly) {
                        // If we're here, one `replaceIfMatch` worked and replaced a character from
                        // the original input. We're not supposed to modify anything in the readOnly
                        // loop, but this avoid duplicating a lot of code Instead, we're just
                        // hidding our mistake
                        array[--write] = oldWriteChar;
                        return true;
                    }
                } else {
                    array[write++] = '&';
                }
            }

            if (readOnly)
                return false;

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

// Two versions of base64, with 2045 being very permissive
//  https://en.wikipedia.org/wiki/Base64#Variants_summary_table
bool PWTransformer::transformDecodeBase64RFC4648(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            if (!readOnly)
                return decodeBase64(array, length);

            // All characters must be valid
            for (uint64_t pos = 0; pos < length; ++pos) {
                if (!isalnum(array[pos]) && array[pos] != '+' && array[pos] != '/') {
                    // If it's not a valid base64, it must be the trailing =
                    if (array[pos] == '=') {
                        uint64_t equalCount = 0;
                        while (pos + equalCount < length && array[pos + equalCount] == '=') {
                            equalCount += 1;
                        }

                        // The = must go to the end, and there musn't be too many
                        const uint64_t maxPaddingNeeded = 4 - (pos % 4);
                        if (pos + equalCount == length && equalCount <= 3 &&
                            equalCount <= maxPaddingNeeded)
                            continue;
                    }

                    // Anything wrong -> nope
                    return false;
                }
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformDecodeBase64RFC2045(ddwaf_object *parameter, bool readOnly)
{
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            if (!readOnly)
                return decodeBase64(array, length);

            uint64_t validChars = 0;
            for (uint64_t pos = 0; pos < length; ++pos) {
                // Something outside the valid range?
                if (!isalnum(array[pos]) && array[pos] != '+' && array[pos] != '/') {
                    // Let's count the equals
                    if (array[pos] == '=') {
                        uint64_t equalCount = 0;
                        while (pos + equalCount < length && array[pos + equalCount] == '=') {
                            equalCount += 1;
                        }

                        // If that's the final padding, we need to make sure there is enough of it.
                        // Otherwise we ignore it
                        if (pos + equalCount == length) {
                            const uint64_t minPaddingNeeded = 4 - (validChars % 4);
                            if (minPaddingNeeded == 4 || minPaddingNeeded <= equalCount)
                                validChars += equalCount;

                            break;
                        } else {
                            pos += equalCount - 1;
                        }
                    }
                } else {
                    // We want to make sure there is at least something to decode
                    validChars += 1;
                }
            }

            // Virtually the only constraint is that it needs to be properly padded
            return validChars && validChars % 4 == 0;
        },
        readOnly);
}

bool PWTransformer::transformEncodeBase64(ddwaf_object *parameter, bool readOnly)
{
    // If that's a non empty string, we can encode it (assuming it's not too long)
    //  We likely could extend to the other scallars but not until someone ask for it
    if (parameter->type != DDWAF_OBJ_STRING || parameter->stringValue == NULL ||
        parameter->nbEntries == 0 || parameter->nbEntries >= UINT64_MAX / 4 * 3) {
        return false;
    }

    if (readOnly)
        return true;

    // We need to allocate a buffer to contain the base64 encoded string
    const uint64_t originalLength = parameter->nbEntries;
    const uint64_t encodedLength = (originalLength + 2) / 3 * 4;
    const uint8_t *oldString = reinterpret_cast<const uint8_t *>(parameter->stringValue);
    char *newString = (char *)malloc((size_t)encodedLength + 1);

    // We don't have a good way to make this test fail in the CI, thus crapping on the coverage
    if (newString == NULL)
        return false;

    const static char b64Encoding[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-'};

    uint64_t read = 0, write = 0;

    for (; read + 2 < originalLength; read += 3) {
        const uint8_t quartet[4] = {static_cast<uint8_t>(oldString[read] >> 2),
            static_cast<uint8_t>((oldString[read] & 0x3) << 4 | (oldString[read + 1] >> 4)),
            static_cast<uint8_t>((oldString[read + 1] & 0xf) << 2 | oldString[read + 2] >> 6),
            static_cast<uint8_t>(oldString[read + 2] & 0x3f)};

        newString[write++] = b64Encoding[quartet[0]];
        newString[write++] = b64Encoding[quartet[1]];
        newString[write++] = b64Encoding[quartet[2]];
        newString[write++] = b64Encoding[quartet[3]];
    }

    if (read != originalLength) {
        // We want to keep our logic simple so let's copy the bytes left in an appropriately sized
        // buffer
        //  We know that must have either one, or two bytes to process (otherwise the loop above
        //  would have run one more time)
        const uint8_t originalBytes[2] = {
            oldString[read], read + 1 == originalLength ? (uint8_t)0 : oldString[read + 1]};

        // Compute the codes, only three as the forth is only set by the third, missing input byte
        const uint8_t convertedBytes[3] = {static_cast<uint8_t>(originalBytes[0] >> 2),
            static_cast<uint8_t>((originalBytes[0] & 0x3) << 4 | (originalBytes[1] >> 4)),
            static_cast<uint8_t>((originalBytes[1] & 0xf) << 2)};

        // The first byte is always set in this branch, so no matter what we must set the first two
        // bytes in the output
        newString[write++] = b64Encoding[convertedBytes[0]];
        newString[write++] = b64Encoding[convertedBytes[1]];

        // If we had 2 bytes to encode, we'll encode it
        // Otherwise, we will pad the end
        if (++read != originalLength) {
            newString[write++] = b64Encoding[convertedBytes[2]];
        } else {
            newString[write++] = '=';
        }

        newString[write++] = '=';
    }

    newString[write] = 0;

    // Update the ddwaf_object
    free((void *)parameter->stringValue);
    parameter->stringValue = newString;
    parameter->nbEntries = write;

    return true;
}

bool PWTransformer::transformCmdLine(ddwaf_object *parameter, bool readOnly)
{
    /*
     * Reimplementing the cmdLine ModSecurity operator.
     * It is documented as follow:
     *
     * The cmdLine transformation function avoids this problem by manipulating the variable contend
     in the following ways:
     * 1. deleting all backslashes [\]
     * 2. deleting all double quotes ["]
     * 3. deleting all single quotes [']
     * 4. deleting all carets [^]
     * 5. deleting spaces before a slash [/]
     * 6. deleting spaces before an open parentesis [(]
     * 7. replacing all commas [,] and semicolon [;] into a space
     * 8. replacing all multiple spaces (including tab, newline, etc.) into one space
     * 9. transform all characters to lowercase

     */
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            uint64_t read = 0;

            // Fast forward, also implement readOnly
            for (; read < length; read += 1) {
                const char c = array[read];

                // Multi char sequences
                if (read + 1 < length) {
                    const char nextC = array[read + 1];

                    // Character we need to trandform (7) or multiple spaces/space equivalent
                    // characters? (5, 6 and 8)
                    if (c == ',' || c == ';' ||
                        (isspace(c) && (isspace(nextC) || nextC == ',' || nextC == ';' ||
                                           nextC == '(' || nextC == '/'))) {
                        if (readOnly)
                            return true;
                        break;
                    }
                }

                // Remove 1, 2, 3 and 4, and detect 9
                if (c == '\\' || c == '"' || c == '\'' || c == '^' || (c >= 'A' && c <= 'Z')) {
                    if (readOnly)
                        return true;
                    break;
                }
            }

            if (readOnly)
                return false;

            uint64_t write = read;
            // Actually perform the update
            for (; read < length; read += 1) {
                const char c = array[read];

                // Remove 1, 2, 3 and 4
                if (c == '\\' || c == '"' || c == '\'' || c == '^') {
                    continue;
                } else if (isspace(c) || c == ',' || c == ';') {
                    // We're doing all the space trimming here:
                    //  We only copy the last space (or space terminator) character

                    // First, we get rid of the case where we're on the last char: we will need to
                    // write a space no matter what then
                    if (read + 1 < length) {
                        // Then, we find if the next char is space equivalent (7, 8) or a space
                        // terminator (5, 6)
                        const char nextC = array[read + 1];
                        const bool isNextSpace = isspace(nextC) || nextC == ',' || nextC == ';' ||
                                                 nextC == '(' || nextC == '/';

                        // If yes, then we drop this character, the next iteration will take care of
                        // it
                        if (isNextSpace)
                            continue;
                    }

                    // Otherwise, we write this last space!
                    array[write++] = ' ';
                }
                // Handle upper case character
                //  We could use a single branch for both cases by calling systematically tolower()
                //  but I'm a bit worried on the perf impact
                else if (c >= 'A' && c <= 'Z') {
                    array[write++] = array[read] | 0x20;
                } else {
                    array[write++] = array[read];
                }
            }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformRemoveComments(ddwaf_object *parameter, bool readOnly)
{
    /* Remove different types of comments:
     *   - C-style comments starting in slash asterisk and ending in asterisk slash.
     *   - HTML comments starting in <!-- and ending in -->.
     *   - Shell-style comments starting in # with no terminator.
     *   - SQL-style comments starting in -- with no terminator.
     * Special considerations:
     *   - Everything after # or -- is removed, since there is no comment terminator.
     *   - If the comment style requires a terminator, but it's missing, everything
     *     after the beginning of the comment will be removed.
     */
    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool readOnly) -> bool {
            enum class CommentType { UNKNOWN, HTML, SHELL, SQL, C } type;
            uint64_t read = 0, write = 0;
            while (read < length) {
                type = CommentType::UNKNOWN;
                while (read < length) {
                    if (array[read] == '<' && read + 3 < length && array[read + 1] == '!' &&
                        array[read + 2] == '-' && array[read + 3] == '-') {
                        read += 4;
                        type = CommentType::HTML;
                        break;
                    } else if (array[read] == '-' && read + 1 < length && array[read] == '-') {
                        // Don't bother updating the read index since we'll exit anyway
                        type = CommentType::SQL;
                        break;
                    } else if (array[read] == '#') {
                        // Don't bother updating the read index since we'll exit anyway
                        type = CommentType::SHELL;
                        break;
                    } else if (array[read] == '/' && read + 1 < length && array[read + 1] == '*') {
                        read += 2;
                        type = CommentType::C;
                        break;
                    }

                    if (!readOnly) {
                        array[write++] = array[read];
                    }
                    ++read;
                }

                // If we're in readOnly mode, we should know by now if the string
                // will need to be transformed.
                if (readOnly) {
                    return type != CommentType::UNKNOWN;
                }

                if (type == CommentType::SHELL || type == CommentType::SQL) {
                    break;
                }

                while (read < length) {
                    void *token = NULL;
                    size_t remaining = (size_t)(length - read);
                    if (type == CommentType::HTML &&
                        (token = memchr(&array[read], '-', remaining))) {
                        read = static_cast<uint64_t>(reinterpret_cast<char *>(token) - array);
                        if (read + 2 < length && array[read + 1] == '-' && array[read + 2] == '>') {
                            read += 3;
                            break;
                        } else {
                            ++read;
                        }
                    } else if (type == CommentType::C &&
                               (token = memchr(&array[read], '*', remaining))) {
                        read = static_cast<uint64_t>(reinterpret_cast<char *>(token) - array);
                        if (read + 1 < length && array[read + 1] == '/') {
                            read += 2;
                            break;
                        } else {
                            ++read;
                        }
                    } else {
                        // If we reach this point we have found no comment terminator
                        // so we set read to length in order to exit.
                        read = length;
                        break;
                    }
                }
            }

            // Technically at this point readOnly is not necessary but this ensures
            // there are no actual stores on `array` when on readOnly.
            if (!readOnly && write < length) {
                array[write] = '\0';
                length = write;
            }

            // In readOnly mode, we want to return false if the string was emtpy
            return !readOnly || read != 0;
        },
        readOnly);
}

bool PWTransformer::transformNumerize(ddwaf_object *parameter, bool readOnly)
{
    if (parameter->type != DDWAF_OBJ_STRING)
        return false;

    if (parameter->stringValue == NULL || parameter->nbEntries == 0)
        return false;

    bool isNegative = parameter->nbEntries > 0 && parameter->stringValue[0] == '-';
    uint64_t value = 0;

    for (uint64_t read = isNegative ? 1 : 0; read < parameter->nbEntries; ++read) {
        if (!isdigit(parameter->stringValue[read]))
            return false;

        value *= 10;
        value += (uint64_t)(parameter->stringValue[read] - '0');
    }

    // Check if the value can be represented as a negative 64bit
    //  Also reject `-`
    if (isNegative && (value > INT64_MAX || parameter->nbEntries == 1))
        return false;

    if (readOnly)
        return true;

    ddwaf_object_free(parameter);

    if (isNegative) {
        ddwaf_object_signed_force(parameter, static_cast<int64_t>(value) * -1ll);
    } else {
        ddwaf_object_unsigned_force(parameter, value);
    }

    return true;
}

bool PWTransformer::transformUnicodeNormalize(ddwaf_object *parameter, bool readOnly)
{
    if (parameter->type != DDWAF_OBJ_STRING)
        return false;

    if (parameter->stringValue == NULL || parameter->nbEntries == 0)
        return false;

    uint32_t codepoint;
    uint64_t position = 0;
    if (readOnly) {
        while ((codepoint = ddwaf::utf8::fetch_next_codepoint(
                    parameter->stringValue, position, parameter->nbEntries)) != UTF8_EOF) {
            // Ignore invalid glyphs or Zero-Width joiners (which we allow for emojis)
            if (codepoint == UTF8_INVALID) {
                continue;
            }

            int32_t decomposedCodepoint = 0;
            size_t decomposedLength =
                ddwaf::utf8::normalize_codepoint(codepoint, &decomposedCodepoint, 1);

            // If the glyph needed decomposition, we flag the string
            if (decomposedLength != 1 || codepoint != (uint32_t)decomposedCodepoint) {
                return true;
            }
        }
        return false;
    }

    return ddwaf::utf8::normalize_string((char **)&parameter->stringValue, parameter->nbEntries);
}

//
// Those three utils are only used when computing targets from an agent target
// We can skip the read-only phase for them, as we don't ever want to use the raw input
//

bool PWTransformer::transformURLBaseName(ddwaf_object *parameter, bool readOnly)
{
    // Skip the read only phase
    if (readOnly) {
        return parameter != NULL && parameter->type == DDWAF_OBJ_STRING;
    }

    // From the following URI: `/path/index.php?a=b`
    //  We need to compute `index.php`

    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool) -> bool {
            size_t endOfPath = 0, lastSlash = 0;

            // Look for the end of the path, and tag the slashes along the way
            while (endOfPath < length && array[endOfPath] != '?' && array[endOfPath] != '#') {
                if (array[endOfPath] == '/') {
                    lastSlash = endOfPath;
                }

                endOfPath += 1;
            }

            // Find the character after the /. We need to be carefull when no slash are present
            const size_t firstAfterSlash =
                (lastSlash != 0 || array[0] == '/') ? lastSlash + 1 : lastSlash;

            // Copy between the last slash and the end of the path
            size_t write = 0, read = firstAfterSlash;
            while (read < endOfPath) { array[write++] = array[read++]; }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

bool PWTransformer::transformURLFilename(ddwaf_object *parameter, bool readOnly)
{
    // Skip the read only phase
    if (readOnly) {
        return parameter != NULL && parameter->type == DDWAF_OBJ_STRING;
    }

    // From the following URI: `/path/index.php?a=b`
    //  We need to compute `/path/index.php`

    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool) -> bool {
            size_t pos = 0;

            while (pos < length && array[pos] != '?' && array[pos] != '#') { pos += 1; }

            length = pos;
            return true;
        },
        readOnly);
}

bool PWTransformer::transformURLQueryString(ddwaf_object *parameter, bool readOnly)
{
    // Skip the read only phase
    if (readOnly) {
        return parameter != NULL && parameter->type == DDWAF_OBJ_STRING;
    }

    // From the following URI: `/path/index.php?a=b`
    //  We need to compute `a=b`

    return runTransform(
        parameter,
        [](char *array, uint64_t &length, bool) -> bool {
            size_t read = 0;

            // Find the end of the path, i.e either the end of the URL, the begining of the query
            // string or the fragment
            while (read < length && array[read] != '?' && array[read] != '#') { read += 1; }

            // If we had a query string, skip past the `?`
            // Otherwise, we want the copy loop to abort immediately
            if (read < length && array[read] == '?') {
                read += 1;
            }

            // Copy until the end of the query string
            size_t write = 0;
            while (read < length && array[read] != '#') { array[write++] = array[read++]; }

            if (write < length) {
                array[write] = 0;
                length = write;
            }

            return true;
        },
        readOnly);
}

// If the transformer is called with readOnly, it needs to return
bool PWTransformer::transform(PW_TRANSFORM_ID transformID, ddwaf_object *parameter, bool readOnly)
{
    switch (transformID) {
    case PWT_LOWERCASE:
        return transformLowerCase(parameter, readOnly);

    case PWT_NONULL:
        return transformNoNull(parameter, readOnly);

    case PWT_COMPRESS_WHITE:
        return transformCompressWhiteSpace(parameter, readOnly);

    case PWT_LENGTH:
        return transformLength(parameter, readOnly);

    case PWT_NORMALIZE:
        return transformNormalize(parameter, readOnly);

    case PWT_NORMALIZE_WIN:
        return transformNormalizeWin(parameter, readOnly);

    case PWT_DECODE_URL:
        return transformDecodeURL(parameter, readOnly, false);

    case PWT_DECODE_URL_IIS: {
        // Repeatedly decode the URL as this is a bypass vector
        //  We don't do it for PWT_DECODE_URL as it's the standard compliant one
        bool output;
        do {
            output = transformDecodeURL(parameter, readOnly, true);
        } while (output && !readOnly && transformDecodeURL(parameter, true, true));
        return output;
    }

    case PWT_DECODE_CSS:
        return transformDecodeCSS(parameter, readOnly);

    case PWT_DECODE_JS:
        return transformDecodeJS(parameter, readOnly);

    case PWT_DECODE_HTML:
        return transformDecodeHTML(parameter, readOnly);

    case PWT_DECODE_BASE64:
        return transformDecodeBase64RFC4648(parameter, readOnly);

    case PWT_DECODE_BASE64_EXT:
        return transformDecodeBase64RFC2045(parameter, readOnly);

    case PWT_ENCODE_BASE64:
        return transformEncodeBase64(parameter, readOnly);

    case PWT_CMDLINE:
        return transformCmdLine(parameter, readOnly);

    case PWT_REMOVE_COMMENTS:
        return transformRemoveComments(parameter, readOnly);

    case PWT_EXTRACT_BASENAME:
        return transformURLBaseName(parameter, readOnly);

    case PWT_EXTRACT_FILENAME:
        return transformURLFilename(parameter, readOnly);

    case PWT_EXTRACT_QUERYSTR:
        return transformURLQueryString(parameter, readOnly);

    case PWT_NUMERIZE:
        return transformNumerize(parameter, readOnly);

    case PWT_UNICODE_NORMALIZE:
        return transformUnicodeNormalize(parameter, readOnly);

    default:
        return false;
    }
}

PW_TRANSFORM_ID PWTransformer::getIDForString(std::string_view str)
{
    if (str == "urlDecodeUni")
        return PWT_DECODE_URL_IIS;
    else if (str == "htmlEntityDecode")
        return PWT_DECODE_HTML;
    else if (str == "jsDecode")
        return PWT_DECODE_JS;
    else if (str == "cssDecode")
        return PWT_DECODE_CSS;
    else if (str == "cmdLine")
        return PWT_CMDLINE;
    else if (str == "base64Decode")
        return PWT_DECODE_BASE64;
    else if (str == "base64DecodeExt")
        return PWT_DECODE_BASE64_EXT;
    else if (str == "urlDecode")
        return PWT_DECODE_URL;
    else if (str == "removeNulls")
        return PWT_NONULL;
    else if (str == "normalizePath")
        return PWT_NORMALIZE;
    else if (str == "normalizePathWin")
        return PWT_NORMALIZE_WIN;
    else if (str == "compressWhiteSpace")
        return PWT_COMPRESS_WHITE;
    else if (str == "lowercase")
        return PWT_LOWERCASE;
    else if (str == "length")
        return PWT_LENGTH;
    else if (str == "base64Encode")
        return PWT_ENCODE_BASE64;
    else if (str == "_sqr_basename")
        return PWT_EXTRACT_BASENAME;
    else if (str == "_sqr_filename")
        return PWT_EXTRACT_FILENAME;
    else if (str == "_sqr_querystring")
        return PWT_EXTRACT_QUERYSTR;
    else if (str == "removeComments")
        return PWT_REMOVE_COMMENTS;
    else if (str == "numerize")
        return PWT_NUMERIZE;
    else if (str == "keys_only")
        return PWT_KEYS_ONLY;
    else if (str == "values_only")
        return PWT_KEYS_ONLY;
    else if (str == "unicode_normalize")
        return PWT_UNICODE_NORMALIZE;

    return PWT_INVALID;
}

bool PWTransformer::doesNeedTransform(
    const std::vector<PW_TRANSFORM_ID> &transformIDs, ddwaf_object *parameter)
{
    if (parameter == NULL)
        return false;

    for (const PW_TRANSFORM_ID &transformID : transformIDs) {
        if (transform(transformID, parameter, true))
            return true;
    }

    return false;
}

static uint8_t fromHex(char c)
{
    if (isdigit(c))
        return (uint8_t)c - '0';

    return (uint8_t)(c | 0x20) - 'a' + 0xa;
}

static bool replaceIfMatch(char *array, uint64_t &readHead, uint64_t &writeHead,
    uint64_t readLengthLeft, const char *token, uint32_t tokenLength, char decodedToken)
{
    if (readLengthLeft < tokenLength)
        return false;

    // Case incensitive match (assume the token is lowercase)
    for (uint32_t pos = 0; pos < tokenLength; ++pos) {
        if ((array[readHead + pos] | 0x20) != *token++)
            return false;
    }

    array[writeHead++] = decodedToken;
    readHead += tokenLength;
    return true;
}

static bool decodeBase64(char *array, uint64_t &length)
{
    /*
     * We ignore the invalid characters in this loop as `doesNeedTransform` will prevent decoding
     * invalid base64 sequences
     */

    const static char b64Reverse[256] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,
        64, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
        38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1};

    uint64_t read = 0, write = 0;

    while (read < length) {
        // Read the next 4 b64 bytes
        char quartet[4] = {0};
        uint8_t pos = 0;

        for (char c; pos < 4 && read < length; ++read) {
            // If a valid base64 character
            if (((c = b64Reverse[(uint8_t)array[read]]) & 0x40) == 0)
                quartet[pos++] = c;
        }

        // Coalesce 4x 6 bits into 3x 8 bits
        const uint32_t coalescedValue =
            (uint32_t)(quartet[0] << 18 | quartet[1] << 12 | quartet[2] << 6 | quartet[3]);

        // Convert to bytes
        const uint8_t bytes[3] = {static_cast<uint8_t>(coalescedValue >> 16),
            static_cast<uint8_t>((coalescedValue >> 8) & 0xff),
            static_cast<uint8_t>(coalescedValue & 0xff)};

        // Simple write
        if (pos == 4) {
            ((uint8_t *)array)[write++] = bytes[0];
            ((uint8_t *)array)[write++] = bytes[1];
            ((uint8_t *)array)[write++] = bytes[2];
        } else if (pos) {
            // This is the final write, we shouldn't write every byte
            // We match CRS behavior of partially decoding a character
            //
            // If pos == 1, we have 6 bits of content, 1 char to write
            // If pos == 2, we have 12 bits of content, 2 char to write
            // If pos == 3, we have 18 bits of content, 3 char to write

            ((uint8_t *)array)[write++] = bytes[0];

            // At least 12 bits of content, only write if either this of the next byte isn't empty
            if (pos > 1 && (bytes[1] || bytes[2]))
                ((uint8_t *)array)[write++] = bytes[1];

            // At least 18 bits of content and non-null
            if (pos > 2 && bytes[2] != 0)
                ((uint8_t *)array)[write++] = bytes[2];
        }
    }

    if (write < length) {
        array[write] = 0;
        length = write;
    }

    return true;
}
