// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "helpers.hpp"
#include "stdio.h"
#include "stdlib.h"

namespace {
size_t get_file_size(FILE *fp)
{
    long size;

    fseek(fp, 0L, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    return size;
}

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

char *read_file_content(const char *filename, size_t *psize)
{
    FILE *fp = fopen(filename, "r");

    if (!fp) {
        fprintf(stderr, "Can't read file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    *psize = get_file_size(fp);
    char *fcontent = (char *)malloc(*psize + 1);

    if (!fcontent) {
        fprintf(stderr, "Can't allocate %lu bytes", *psize);
        exit(EXIT_FAILURE);
    }

    fread(fcontent, 1, *psize, fp);
    fclose(fp);

    fcontent[*psize] = 0;

    return fcontent;
}
