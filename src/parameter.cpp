// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <cinttypes>
#include <exception.hpp>
#include <parameter.hpp>

namespace {

const std::string strtype(int type)
{
    switch (type) {
    case DDWAF_OBJ_MAP:
        return "map";
    case DDWAF_OBJ_ARRAY:
        return "array";
    case DDWAF_OBJ_STRING:
        return "string";
    }
    return "unknown";
}

} // namespace

namespace ddwaf {
static void print_(parameter args, uint64_t depth)
{
    for (uint64_t i = 0; i < depth; ++i) { std::printf("  "); }

    switch (args.type) {
    case DDWAF_OBJ_INVALID:
        std::printf("- invalid\n");
        break;
    case DDWAF_OBJ_BOOL:
        std::printf("- %s\n", args.boolean ? "true" : "false");
        break;
    case DDWAF_OBJ_SIGNED: {
        if (args.parameterName != NULL)
            std::printf("- %s: %" PRId64 "\n", args.parameterName, args.intValue);
        else
            std::printf("- %" PRId64 "\n", args.intValue);
        break;
    }

    case DDWAF_OBJ_UNSIGNED: {
        if (args.parameterName != NULL)
            std::printf("- %s: %" PRIu64 "\n", args.parameterName, args.uintValue);
        else
            std::printf("- %" PRIu64 "\n", args.uintValue);
        break;
    }

    case DDWAF_OBJ_STRING: {
        if (args.parameterName != NULL)
            std::printf("- %s: %s\n", args.parameterName, args.stringValue);
        else
            std::printf("- %s\n", args.stringValue);
        break;
    }

    case DDWAF_OBJ_ARRAY: {
        if (args.parameterName != NULL)
            std::printf("- %s:\n", args.parameterName);

        for (uint64_t i = 0; i < args.nbEntries; ++i) print_(args.array[i], depth + 1);
        break;
    }

    case DDWAF_OBJ_MAP: {
        if (args.parameterName != NULL)
            std::printf("- %s:\n", args.parameterName);

        for (uint64_t i = 0; i < args.nbEntries; ++i) print_(args.array[i], depth + 1);
        break;
    }
    }
}

void parameter::print() { print_(*this, 0); }

parameter::operator parameter::map()
{
    if (type != DDWAF_OBJ_MAP) {
        throw bad_cast("map", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return parameter::map();
    }

    std::unordered_map<std::string_view, parameter> map;
    map.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        const parameter &kv = array[i];
        if (kv.parameterName == nullptr) {
            throw malformed_object("invalid key on map entry");
        }

        map.emplace(std::string_view(kv.parameterName, kv.parameterNameLength), kv);
    }

    return map;
}

parameter::operator parameter::vector()
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return parameter::vector();
    }
    return std::vector<parameter>(array, array + nbEntries);
}

parameter::operator parameter::string_set()
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return parameter::string_set();
    }

    parameter::string_set set;
    set.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        if (array[i].type != DDWAF_OBJ_STRING) {
            throw malformed_object("item in array not a string, can't cast to string set");
        }

        set.emplace(array[i].stringValue, array[i].nbEntries);
    }

    return set;
}

parameter::operator std::string_view()
{
    if (type != DDWAF_OBJ_STRING || stringValue == nullptr) {
        throw bad_cast("string", strtype(type));
    }

    return std::string_view(stringValue, nbEntries);
}

parameter::operator std::string()
{
    if (type != DDWAF_OBJ_STRING || stringValue == nullptr) {
        throw bad_cast("string", strtype(type));
    }

    return std::string(stringValue, nbEntries);
}

parameter::operator uint64_t()
{
    if (type == DDWAF_OBJ_UNSIGNED) {
        return uintValue;
    } else if (type == DDWAF_OBJ_STRING && stringValue != nullptr) {
        uint64_t result;
        auto end{&stringValue[nbEntries]};
        auto [endConv, err] = std::from_chars(stringValue, end, result);
        if (err == std::errc{} && endConv == end) {
            return result;
        }
    }

    throw bad_cast("unsigned", strtype(type));
}

parameter::operator bool()
{
    if (type == DDWAF_OBJ_BOOL) {
        return boolean;
    }

    throw bad_cast("bool", strtype(type));
}

parameter::operator std::vector<std::string>()
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    std::vector<std::string> data;
    data.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        if (array[i].type != DDWAF_OBJ_STRING) {
            throw malformed_object("item in array not a string, can't cast to string vector");
        }

        data.emplace_back(array[i].stringValue, array[i].nbEntries);
    }

    return data;
}

parameter::operator std::vector<std::string_view>()
{
    if (type != DDWAF_OBJ_ARRAY) {
        throw bad_cast("array", strtype(type));
    }

    if (array == nullptr || nbEntries == 0) {
        return {};
    }

    std::vector<std::string_view> data;
    data.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++) {
        if (array[i].type != DDWAF_OBJ_STRING) {
            throw malformed_object("item in array not a string, can't cast to string_view vector");
        }

        data.emplace_back(array[i].stringValue, array[i].nbEntries);
    }

    return data;
}

} // namespace ddwaf
