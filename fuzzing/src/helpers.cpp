// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <fstream>
#include <ios>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include "helpers.hpp"


namespace {

void indent(int i) { fprintf(stderr, "\n%*s", i * 4, ""); }

void print_string(const char *buffer, uint64_t size)
{
    if (buffer == NULL) {
        fprintf(stderr, "<NULL_PTR>");
        return;
    }

    fprintf(stderr, "\"");
    for (uint64_t i = 0; i < size; i++) {
        if (buffer[i] == 34) {
            fprintf(stderr, "\\\"");
        } else if (buffer[i] == 92) {
            fprintf(stderr, "\\\\");
        } else if (buffer[i] >= 32 && buffer[i] <= 127) {
            fprintf(stderr, "%c", buffer[i]);
        } else {
            fprintf(stderr, "\\x%02x", buffer[i]);
        }
    }
    fprintf(stderr, "\"");
}

void _print_object(ddwaf_object entry, uint8_t depth)
{
    bool first = true;

    switch (entry.type) {
    case DDWAF_OBJ_MAP:
        if (entry.nbEntries == 0) {
            fprintf(stderr, "{}");
        } else {

            fprintf(stderr, "{");

            for (uint64_t i = 0; i < entry.nbEntries; i++) {
                if (first) {
                    first = false;
                } else {
                    fprintf(stderr, ",");
                }

                indent(depth + 1);
                print_string(entry.array[i].parameterName, entry.array[i].parameterNameLength);
                fprintf(stderr, ": ");
                _print_object(entry.array[i], depth + 1);
            }

            indent(depth);
            fprintf(stderr, "}");
        }
        break;

    case DDWAF_OBJ_ARRAY:
        if (entry.nbEntries == 0) {
            indent(depth);
            fprintf(stderr, "[]");
        } else {
            fprintf(stderr, "[");

            for (uint64_t i = 0; i < entry.nbEntries; i++) {
                if (first) {
                    first = false;
                } else {
                    fprintf(stderr, ",");
                }
                indent(depth + 1);
                _print_object(entry.array[i], depth + 1);
            }

            indent(depth);
            fprintf(stderr, "]");
        }

        break;

    case DDWAF_OBJ_SIGNED:
        fprintf(stderr, "%ld", entry.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        fprintf(stderr, "%lu", entry.uintValue);
        break;
    case DDWAF_OBJ_STRING:
        print_string(entry.stringValue, entry.nbEntries);
        break;
    case DDWAF_OBJ_BOOL:
        fprintf(stderr, "%s", entry.boolean ? "true" : "false");
        break;
    case DDWAF_OBJ_INVALID:
        fprintf(stderr, "--PW ERROR--");
        break;
    }
}

} // namespace

void print_object(ddwaf_object entry)
{
    _print_object(entry, 0);
    fprintf(stderr, "\n");
}

std::string read_file(std::string_view filename)
{
    std::ifstream file(filename.data(), std::ios::in);
    if (!file)
    {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.seekg(0, std::ios::end);
    buffer.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    file.close();

    return buffer;
}

