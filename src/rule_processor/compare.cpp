// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>

#include <IPWRuleProcessor.h>
#include <utils.h>

int Compare::performCompare(uint64_t data, uint64_t length, DDWAF_OBJ_TYPE type) const
{
    // The value should only be either a string or a number
    if (internalValue.type == DDWAF_OBJ_STRING)
    {
        //Because of the definition of ddwaf_object, the agent is allowed to send 0 bytes in strings.
        //	String may also not be 0-terminated
        //	This logic need to check for that

        size_t lengthSize = (size_t) length;

        //Will return a negative value if data is "lower" than internalValue
        size_t internalLength = internalValue.stringValue.length();
        int output            = memcmp((const void*) data, internalValue.stringValue.c_str(), std::min(lengthSize, internalLength));

        // We only compare the strings up until the shortest string end.
        //  If they match on this segment, we return the shortest string as the "lowest"
        return output == 0 ? (int) (length - internalLength) : output;
    }

    // If it's a number, we have to deal with signedness fun
    //	We quickly turn the encoded value into something easier to deal with
    union
    {
        int64_t s;
        uint64_t u;
    } value;
    value.u = data;

    // Then we see if the comparaison is possible
    if (type == DDWAF_OBJ_SIGNED && internalValue.type != DDWAF_OBJ_SIGNED)
    {
        //Value is negative, and we're trying to compare to an unsigned value... we already know we're lower :)
        if (value.s < 0)
            return -1;

        type = DDWAF_OBJ_UNSIGNED;
    }
    else if (type == DDWAF_OBJ_UNSIGNED && internalValue.type != DDWAF_OBJ_UNSIGNED)
    {
        // If the value is larger than the maximum encodable value in our signed storage, we can stop right now :)
        if (value.u > INT64_MAX)
            return 1;

        type = DDWAF_OBJ_SIGNED;
    }

    switch (type)
    {
        case DDWAF_OBJ_SIGNED:
        {
            if (value.s > internalValue.signedInt)
                return 1;
            else if (value.s == internalValue.signedInt)
                return 0;
            else
                return -1;
        }

        case DDWAF_OBJ_UNSIGNED:
        {
            if (value.u > internalValue.unsignedInt)
                return 1;
            else if (value.u == internalValue.unsignedInt)
                return 0;
            else
                return -1;
        }

        default:
            return false;
    }
}

bool Compare::perform(uint64_t data, uint64_t length, DDWAF_OBJ_TYPE type, MatchGatherer& gatherer) const
{
    bool didMatch = matchFromCompare(performCompare(data, length, type));
    bool output   = didMatch == wantMatch;

    if (output)
    {
        switch (type)
        {
            case DDWAF_OBJ_STRING:
                gatherer.resolvedValue = std::string((const char*) data, (size_t) length);
                break;

            case DDWAF_OBJ_SIGNED:
                gatherer.resolvedValue = std::to_string(((int64_t) data));
                break;

            case DDWAF_OBJ_UNSIGNED:
                gatherer.resolvedValue = std::to_string(data);
                break;

            default:
                output = false;
                break;
        }
    }

    return output;
}

Compare::Compare(const char* refName, uint64_t command) : IPWRuleProcessor(refName, command)
{
    internalValue.type = DDWAF_OBJ_INVALID;
}

bool Compare::buildProcessor(const rapidjson::Value& value, bool)
{
    switch (value.GetType())
    {
        case rapidjson::kStringType:
        {
            internalValue.type        = DDWAF_OBJ_STRING;
            internalValue.stringValue = std::string(value.GetString(), value.GetStringLength());
            return true;
        }

        case rapidjson::kNumberType:
        {
            if (value.IsDouble())
            {
                return false;
            }
            else if (value.IsUint64())
            {
                internalValue.type        = DDWAF_OBJ_UNSIGNED;
                internalValue.unsignedInt = value.GetUint64();
            }
            else
            {
                internalValue.type      = DDWAF_OBJ_SIGNED;
                internalValue.signedInt = value.GetInt64();
            }
            return true;
        }

        case rapidjson::kTrueType:
        {
            internalValue.type        = DDWAF_OBJ_UNSIGNED;
            internalValue.unsignedInt = 1;
            return true;
        }

        case rapidjson::kFalseType:
        {
            internalValue.type        = DDWAF_OBJ_UNSIGNED;
            internalValue.unsignedInt = 0;
            return true;
        }

        default:
            return false;
    }
}

bool Compare::doesMatch(const ddwaf_object* pattern, MatchGatherer& gatherer) const
{
    return perform(pattern->uintValue, pattern->nbEntries, pattern->type, gatherer);
}

bool Compare::doesMatchKey(const ddwaf_object* pattern, MatchGatherer& gatherer) const
{
    if (pattern->parameterName == nullptr || internalValue.type != DDWAF_OBJ_STRING)
        return false;

    // Assume the pointer type is smaller or as large as uint64_t
    return perform((uint64_t) pattern->parameterName, pattern->parameterNameLength, DDWAF_OBJ_STRING, gatherer);
}

uint64_t Compare::expectedTypes() const
{
    //Compatibility layer for mixed signedness
    if (internalValue.type == DDWAF_OBJ_SIGNED || internalValue.type == DDWAF_OBJ_UNSIGNED)
        return DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED;

    return internalValue.type;
}

bool Compare::hasStringRepresentation() const
{
    return true;
}

const std::string Compare::getStringRepresentation() const
{
    if (internalValue.type == DDWAF_OBJ_STRING)
    {
        return internalValue.stringValue;
    }
    else if (internalValue.type == DDWAF_OBJ_SIGNED)
    {
        return std::to_string(internalValue.signedInt);
    }
    else
    {
        return std::to_string(internalValue.unsignedInt);
    }
}

//Discard this function as it's too restricted for us
bool Compare::performMatch(const char*, size_t, MatchGatherer&) const
{
    return false;
}

bool Equal::matchFromCompare(const int compareResult) const
{
    return compareResult == 0;
}

bool GreaterThan::matchFromCompare(const int compareResult) const
{
    return compareResult > 0;
}

bool GreaterOrEqual::matchFromCompare(const int compareResult) const
{
    return compareResult >= 0;
}

bool LessThan::matchFromCompare(const int compareResult) const
{
    return compareResult < 0;
}

bool LessOrEqual::matchFromCompare(const int compareResult) const
{
    return compareResult <= 0;
}
