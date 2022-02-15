// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
//
#include <inttypes.h>
#include <stdint.h>
#include <string>
#include <stdexcept>
#include <log.hpp>
#include <validator.hpp>

namespace ddwaf
{

validator::validator(uint64_t max_array_length, uint64_t max_map_depth)
    : max_array_length_(max_array_length), max_map_depth_(max_map_depth)
{
    //Do the limits make sense?
    if (max_map_depth_ == 0)
    {
        DDWAF_DEBUG("Illegal WAF call: sanitization constant 'max_map_depth' should be a positive value");
        throw std::invalid_argument("max_map_depth should be a positive value");
    }

    if (max_array_length_ == 0)
    {
        DDWAF_DEBUG("Illegal WAF call: sanitization constant 'max_array_length' should be a positive value");
        throw std::invalid_argument("max_array_length should be a positive value");
    }
}

bool validator::validate(ddwaf_object input) const
{
    DDWAF_TRACE("Sanitizing WAF parameters");

    //Is the input even remotely valid
    if (input.type != DDWAF_OBJ_MAP)
    {
        DDWAF_DEBUG("Illegal WAF call: parameter structure isn't a map!");
        return false;
    }

    //Note: map can be empty
    if (input.nbEntries != 0 && input.array == nullptr)
    {
        DDWAF_DEBUG("Illegal WAF call: parameter structure claim not to be empty but actually is");
        return false;
    }

    // Sanitize the parameters, and if they're all good, insert them in the array
    const ddwaf_object* mainArray = input.array;
    for (size_t i = 0; i < input.nbEntries; ++i)
    {
        const char* parameterName = mainArray[i].parameterName;

        if (parameterName == nullptr)
        {
            DDWAF_DEBUG("Parameter #%zu doesn't have a name!", i);
            return false;
        }

        DDWAF_TRACE("Sanitizing parameter %s", parameterName);

        if (!validate_helper(mainArray[i]))
        {
            DDWAF_DEBUG("Sanitizing parameter %s failed!", parameterName);
            return false;
        }
    }

    DDWAF_TRACE("Parameter sanitization was successfull");
    return true;
}


bool validator::validate_helper(ddwaf_object input, uint64_t depth) const
{
    if (depth > max_map_depth_)
    {
        DDWAF_DEBUG("Validation error: Structure depth exceed the allowed limit!");
        return false;
    }

    switch (input.type)
    {
        case DDWAF_OBJ_SIGNED:
        case DDWAF_OBJ_UNSIGNED:
        {
            if (input.nbEntries != 0)
            {
                DDWAF_DEBUG("Validation error: Trying to encode an integer but nbEntries isn't 0");
                return false;
            }
            break;
        }

        case DDWAF_OBJ_STRING:
        {
            if (input.stringValue == nullptr)
            {
                DDWAF_DEBUG("Validation error: Trying to encode a string but payload is null");
                return false;
            }
            break;
        }

        case DDWAF_OBJ_ARRAY:
        case DDWAF_OBJ_MAP:
        {
            if (input.nbEntries != 0 && input.array == nullptr)
            {
                DDWAF_DEBUG("Validation error: Array claim not to be empty but actually is");
                return false;
            }

            else if (input.nbEntries > max_array_length_)
            {
                DDWAF_DEBUG("Validation error: Array is unacceptably long");
                return false;
            }

            const bool isMap = input.type == DDWAF_OBJ_MAP;

            const ddwaf_object* array = input.array;
            for (uint64_t i = 0; i < input.nbEntries; ++i)
            {
                //Arrays aren't allowed to have parameter names but maps must have them
                // Therefore, unless hasParamName == isMap, something is wrong
                bool hasParamName = array[i].parameterName != nullptr;
                if (hasParamName != isMap)
                {
                    DDWAF_DEBUG("Validation error: key name are mandatory in maps (%u - %s)", isMap, (hasParamName ? array[i].parameterName : "(null)"));
                    return false;
                }

                if (isMap)
                {
                    DDWAF_TRACE("Performing recursive validation of key %s", array[i].parameterName);
                }
                else
                {
                    DDWAF_TRACE("Performing recursive validation of item #" PRIu64, i);
                }

                if (!validate_helper(array[i], depth + 1))
                {
                    DDWAF_DEBUG("Validation error: the recursive validation failed");
                    return false;
                }
            }
            break;
        }

        default:
            DDWAF_DEBUG("Validation error: Unrecognized type %u", input.type);
            return false;
    }

    return true;
}

}
