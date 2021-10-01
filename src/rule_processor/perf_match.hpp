// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef perf_match_h
#define perf_match_h

#include <memory>

#ifndef AC_H
struct ac_t;
#endif

class PerfMatch : public IPWRuleProcessor
{
public:
    PerfMatch(std::vector<const char*> pattern, std::vector<uint32_t> lengths);
    std::string_view operatorName() const override { return name; }

protected:
    bool performMatch(const char* patternValue, size_t patternLength, MatchGatherer& gatherer) const override;

protected:
    static constexpr std::string_view name { "phrase_match" };
    std::unique_ptr<ac_t, void (*)(void*)> ac { nullptr, nullptr };
};

#endif /* perf_match_h */
