// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <iostream>
#include <list>
#include <utils.hpp>

size_t find_string_cutoff(const char *str, size_t length, uint32_t max_string_length)
{
    // If the string is shorter than our cap, then fine
    if (length <= max_string_length) {
        return length;
    }

    // If it's longer, we need to truncate it. However, we don't want to cut a UTF-8 byte sequence
    // in the middle of it! Valid UTF8 has a specific binary format. 	If it's a single byte UTF8
    // character, then it is always of form '0xxxxxxx', where 'x' is any binary digit. 	If it's a
    // two byte UTF8 character, then it's always of form '110xxxxx 10xxxxxx'. 	Similarly for three
    // and four byte UTF8 characters it starts with '1110xxxx' and '11110xxx' followed 		by
    // '10xxxxxx' one less times as there are bytes.

    // We take the two strongest bits of the first trimmed character. We have four possibilities:
    //  - 00 or 01: single UTF-8 byte, no risk trimming
    //  - 11: New multi-byte sequence, we can ignore it, no risk trimming
    //  - 10: Middle of multi byte sequence, we need to step back
    //  We therefore loop as long as we see the '10' sequence

    size_t pos = max_string_length;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    while (pos != 0 && (str[pos] & 0xC0) == 0x80) { pos -= 1; }

    return pos;
}

namespace ddwaf::object {

void clone_helper(const ddwaf_object &source, ddwaf_object &destination)
{
    switch (source.type) {
    case DDWAF_OBJ_BOOL:
        ddwaf_object_bool(&destination, source.boolean);
        break;
    case DDWAF_OBJ_STRING:
        ddwaf_object_stringl(&destination, source.stringValue, source.nbEntries);
        break;
    case DDWAF_OBJ_SIGNED:
        ddwaf_object_signed_force(&destination, source.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        ddwaf_object_unsigned_force(&destination, source.uintValue);
        break;
    case DDWAF_OBJ_FLOAT:
        ddwaf_object_float(&destination, source.floatValue);
        break;
    case DDWAF_OBJ_INVALID:
        ddwaf_object_invalid(&destination);
        break;
    case DDWAF_OBJ_NULL:
        ddwaf_object_null(&destination);
        break;
    case DDWAF_OBJ_MAP:
        ddwaf_object_map(&destination);
        break;
    case DDWAF_OBJ_ARRAY:
        ddwaf_object_array(&destination);
        break;
    }
}

ddwaf_object clone(ddwaf_object *input)
{
    ddwaf_object tmp;
    ddwaf_object_invalid(&tmp);

    ddwaf_object copy;
    std::list<std::pair<ddwaf_object *, ddwaf_object *>> queue;

    clone_helper(*input, copy);
    if (is_container(input)) {
        queue.emplace_front(input, &copy);
    }

    while (!queue.empty()) {
        auto [source, destination] = queue.front();
        for (uint64_t i = 0; i < source->nbEntries; ++i) {
            const auto &child = source->array[i];
            clone_helper(child, tmp);
            if (source->type == DDWAF_OBJ_MAP) {
                ddwaf_object_map_addl(
                    destination, child.parameterName, child.parameterNameLength, &tmp);
            } else if (source->type == DDWAF_OBJ_ARRAY) {
                ddwaf_object_array_add(destination, &tmp);
            }
        }

        for (uint64_t i = 0; i < source->nbEntries; ++i) {
            if (is_container(&source->array[i])) {
                queue.emplace_back(&source->array[i], &destination->array[i]);
            }
        }

        queue.pop_front();
    }

    return copy;
}

} // namespace ddwaf::object
