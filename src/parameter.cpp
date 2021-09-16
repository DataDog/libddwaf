// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cinttypes>
#include <exception.hpp>
#include <parameter.hpp>
namespace
{

const std::string strtype(int type)
{
    switch (type)
    {
        case DDWAF_OBJ_MAP:
            return "map";
        case DDWAF_OBJ_ARRAY:
            return "array";
        case DDWAF_OBJ_STRING:
            return "string";
    }
    return "unknown";
}

}

namespace ddwaf
{
static void print_(parameter args, uint64_t depth)
{
    for (uint64_t i = 0; i < depth; ++i)
    {
        std::printf("  ");
    }

    switch (args.type)
    {
        case DDWAF_OBJ_INVALID:
            std::printf("- invalid\n");
            break;
        case DDWAF_OBJ_SIGNED:
        {
            if (args.parameterName != NULL)
                std::printf("- %s: %" PRId64 "\n", args.parameterName, args.intValue);
            else
                std::printf("- %" PRId64 "\n", args.intValue);
            break;
        }

        case DDWAF_OBJ_UNSIGNED:
        {
            if (args.parameterName != NULL)
                std::printf("- %s: %" PRIu64 "\n", args.parameterName, args.uintValue);
            else
                std::printf("- %" PRIu64 "\n", args.uintValue);
            break;
        }

        case DDWAF_OBJ_STRING:
        {
            if (args.parameterName != NULL)
                std::printf("- %s: %s\n", args.parameterName, args.stringValue);
            else
                std::printf("- %s\n", args.stringValue);
            break;
        }

        case DDWAF_OBJ_ARRAY:
        {
            if (args.parameterName != NULL)
                std::printf("- %s:\n", args.parameterName);

            for (uint64_t i = 0; i < args.nbEntries; ++i)
                print_(args.array[i], depth + 1);
            break;
        }

        case DDWAF_OBJ_MAP:
        {
            if (args.parameterName != NULL)
                std::printf("- %s:\n", args.parameterName);

            for (uint64_t i = 0; i < args.nbEntries; ++i)
                print_(args.array[i], depth + 1);
            break;
        }
    }
}

void parameter::print() { print_(*this, 0); }

parameter::operator parameter::map()
{
    if (type != DDWAF_OBJ_MAP)
    {
        throw bad_cast("parameter " + strtype(type) + " -> map");
    }

    if (array == nullptr || nbEntries == 0)
    {
        return parameter::map();
    }

    std::unordered_map<std::string_view, parameter> map;
    map.reserve(nbEntries);
    for (unsigned i = 0; i < nbEntries; i++)
    {
        const parameter& kv = array[i];
        if (kv.parameterName == nullptr)
        {
            throw bad_cast("invalid key on parameter map entry");
        }

        map.emplace(std::string_view(kv.parameterName, kv.parameterNameLength), kv);
    }

    return map;
}

parameter::operator parameter::vector()
{
    if (type != DDWAF_OBJ_ARRAY)
    {
        throw bad_cast("parameter(" + strtype(type) + ") -> vector");
    }

    if (array == nullptr || nbEntries == 0)
    {
        return parameter::vector();
    }
    return std::vector<parameter>(array, array + nbEntries);
}

parameter::operator std::string_view()
{
    if (type != DDWAF_OBJ_STRING || stringValue == nullptr)
    {
        throw bad_cast("parameter " + strtype(type) + " -> string_view");
    }

    return std::string_view(stringValue, nbEntries);
}

parameter::operator std::string()
{
    if (type != DDWAF_OBJ_STRING || stringValue == nullptr)
    {
        throw bad_cast("parameter " + strtype(type) + " -> string");
    }

    return std::string(stringValue, nbEntries);
}

}
