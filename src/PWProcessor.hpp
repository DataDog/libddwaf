// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWProcessor_hpp
#define PWProcessor_hpp

#include <rapidjson/document.h>
#include <string>
#include <unordered_map>

#include <PWRet.hpp>
#include <object_store.hpp>
#include <clock.hpp>
#include <rule.hpp>
#include <utils.h>

class PWProcessor
{
public:
    PWProcessor(ddwaf::object_store& input,
        const PWManifest &manifest, const ddwaf::rule_vector& rules);
    bool runFlow(const std::string& name,
                 const ddwaf::rule_ref_vector& flow,
                 PWRetManager& manager,
                 const ddwaf::monotonic_clock::time_point& deadline);

    bool isFirstRun() const;
protected:
    ddwaf::object_store& parameters;
    const PWManifest& manifest_;
    const ddwaf::rule_vector& rules;

    std::unordered_map<ddwaf::rule::index_type, ddwaf::condition::status> ranCache;

    ddwaf::condition::status hasCacheHit(ddwaf::rule::index_type rule_idx) const;
    bool shouldIgnoreCacheHit(const std::vector<ddwaf::condition>& rules) const;

#ifdef TESTING
    FRIEND_TEST(TestPWProcessor, TestCache);
    FRIEND_TEST(TestPWProcessor, TestMultiFlowCacheReport);
    FRIEND_TEST(TestPWProcessor, TestCacheReport);
#endif

};

#endif /* PWProcessor_hpp */
