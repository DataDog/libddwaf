// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWRuleManager_hpp
#define PWRuleManager_hpp

#include <string>
#include <unordered_map>
#include <vector>

struct PWRuleManager;

#include <PWManifest.h>
#include <PWRule.hpp>

struct PWRuleManager
{
    std::unordered_map<std::string, std::vector<PWRule>> rules;
    size_t nbRules;

public:
    PWRuleManager();
    void addRule(const std::string& key, std::vector<PWRule>&& value);
    bool isEmpty() const;
    size_t getNbRules() const;
    bool hasRule(const std::string& name) const;
    const std::vector<PWRule>& getRules(const std::string& name) const;
};

#endif /* PWRuleManager_hpp */
