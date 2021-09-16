// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef compare_h
#define compare_h

struct Compare : public IPWRuleProcessor
{
    struct ValueRepresentation
    {
        std::string stringValue;
        union
        {
            int64_t signedInt;
            uint64_t unsignedInt;
        };
        DDWAF_OBJ_TYPE type;
    };

    ValueRepresentation internalValue;

    int performCompare(uint64_t data, uint64_t length, DDWAF_OBJ_TYPE type) const;
    virtual bool matchFromCompare(const int compareResult) const = 0;
    bool perform(uint64_t data, uint64_t length, DDWAF_OBJ_TYPE type, MatchGatherer& gatherer) const;
    Compare(const char* refName, uint64_t command);
    bool buildProcessor(const rapidjson::Value& value, bool) override;
    bool doesMatch(const ddwaf_object* pattern, MatchGatherer& gatherer) const override;
    bool doesMatchKey(const ddwaf_object* pattern, MatchGatherer& gatherer) const override;
    uint64_t expectedTypes() const override;
    bool hasStringRepresentation() const override;
    const std::string getStringRepresentation() const override;
    bool performMatch(const char*, size_t, MatchGatherer&) const override;
};

class Equal : public Compare
{
    using Compare::Compare; //Use the Compare constructor
    bool matchFromCompare(const int compareResult) const override;
};

class GreaterThan : public Compare
{
    using Compare::Compare;
    bool matchFromCompare(const int compareResult) const override;
};

class GreaterOrEqual : public Compare
{
    using Compare::Compare;
    bool matchFromCompare(const int compareResult) const override;
};

class LessThan : public Compare
{
    using Compare::Compare;
    bool matchFromCompare(const int compareResult) const override;
};

class LessOrEqual : public Compare
{
    using Compare::Compare;
    bool matchFromCompare(const int compareResult) const override;
};

#endif /* compare_h */
