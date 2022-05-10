// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWArgsWrapper_h
#define PWArgsWrapper_h

#include <functional>
#include <set>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <iterator.hpp>
#include <IPWRuleProcessor.h>
#include <PWManifest.h>
#include <utils.h>
#include <validator.hpp>

struct RuleMatchTarget;

class PWRetriever
{
public:
    PWRetriever(const PWManifest& _manifest,
        const ddwaf::object_limits &limits = ddwaf::object_limits());
    void addParameter(const ddwaf_object input);
    bool hasNewArgs() const;
    bool isKeyInLastBatch(PWManifest::ARG_ID key) const;

    Iterator& getIterator(const std::vector<PWManifest::ARG_ID>& targets);

    void resetMatchSession(bool runOnNew);

    bool isValid() const;

    friend class ArgsIterator;
    friend class Iterator;

protected:
    const PWManifest& manifest;
    uint32_t max_depth;
    Iterator internalIterator;

    std::unordered_set<PWManifest::ARG_ID> newestBatch;
        std::unordered_map<std::string, const ddwaf_object*> parameters;
    bool runOnNewOnly = false;

    const ddwaf_object* getParameter(const PWManifest::ARG_ID paramID);

#ifdef TESTING
    FRIEND_TEST(TestAdditive, SelectiveRerun);
    FRIEND_TEST(TestPWManifest, TestUnknownArgID);
#endif
};

#endif /* PWArgsWrapper_h */
