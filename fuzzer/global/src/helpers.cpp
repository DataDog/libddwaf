// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include "helpers.hpp"

namespace {

void indent(int i) { std::cerr << '\n' << std::setw(i * 4) << std::setfill(' ') << ""; }

void print_string(const char *buffer, uint64_t size)
{
    if (buffer == nullptr) {
        std::cerr << "<NULL_PTR>";
        return;
    }

    std::cerr << "\"";
    for (uint64_t i = 0; i < size; i++) {
        if (buffer[i] == 34) {
            std::cerr << "\\\"";
        } else if (buffer[i] == 92) {
            std::cerr << "\\\\";
        } else if (buffer[i] >= 32 && buffer[i] <= 127) {
            std::cerr << buffer[i];
        } else {
            std::cerr << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(buffer[i]) << '\n';
        }
    }
    std::cerr << "\"";
}

// NOLINTNEXTLINE(misc-no-recursion)
void _print_object(ddwaf_object entry, uint8_t depth)
{
    bool first = true;

    switch (entry.type) {
    case DDWAF_OBJ_MAP:
        if (ddwaf_object_size(&entry) == 0) {
            std::cerr << "{}";
        } else {

            std::cerr << "{";

            for (uint64_t i = 0; i < ddwaf_object_size(&entry); i++) {
                if (first) {
                    first = false;
                } else {
                    std::cerr << ",";
                }

                indent(depth + 1);
                const ddwaf_object *key = ddwaf_object_at_key(&entry, i);
                size_t key_len;
                const char *key_data = ddwaf_object_get_string(key, &key_len);
                print_string(key_data, key_len);
                std::cerr << ": ";

                const ddwaf_object *val = ddwaf_object_at_value(&entry, i);
                _print_object(*val, depth + 1);
            }

            indent(depth);
            std::cerr << "}";
        }
        break;

    case DDWAF_OBJ_ARRAY:
        if (ddwaf_object_size(&entry) == 0) {
            indent(depth);
            std::cerr << "[]";
        } else {
            std::cerr << "[";

            for (uint64_t i = 0; i < ddwaf_object_size(&entry); i++) {
                if (first) {
                    first = false;
                } else {
                    std::cerr << ",";
                }
                indent(depth + 1);
                _print_object(*ddwaf_object_at_value(&entry, i), depth + 1);
            }

            indent(depth);
            std::cerr << "]";
        }

        break;
    case DDWAF_OBJ_FLOAT:
        std::cerr << ddwaf_object_get_float(&entry);
        break;
    case DDWAF_OBJ_SIGNED:
        std::cerr << ddwaf_object_get_signed(&entry);
        break;
    case DDWAF_OBJ_UNSIGNED:
        std::cerr << ddwaf_object_get_unsigned(&entry);
        break;
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_LITERAL_STRING:
    case DDWAF_OBJ_LARGE_STRING:
    case DDWAF_OBJ_SMALL_STRING: {
        size_t len;
        const char *data = ddwaf_object_get_string(&entry, &len);
        print_string(data, len);
        break;
    }
    case DDWAF_OBJ_BOOL:
        std::cerr << std::boolalpha << ddwaf_object_get_bool(&entry);
        break;
    case DDWAF_OBJ_NULL:
        std::cerr << "(null)";
        break;
    case DDWAF_OBJ_INVALID:
        std::cerr << "--PW ERROR--";
        break;
    }
}

} // namespace

void print_object(ddwaf_object object)
{
    _print_object(object, 0);
    std::cerr << "\n";
}

std::string read_file(std::string_view filename)
{
    std::ifstream file(filename.data(), std::ios::in);
    if (!file) {
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
