// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWRule.hpp>
#include <PWRuleManager.hpp>
#include <utils.h>

PWRuleManager::PWRuleManager() : nbRules(0) {}

void PWRuleManager::addRule(const std::string& key, std::vector<PWRule>&& value)
{
    nbRules += value.size();
    rules.emplace(key, std::move(value));
}

bool PWRuleManager::isEmpty() const
{
    return rules.empty();
}

size_t PWRuleManager::getNbRules() const
{
    return rules.size();
}

bool PWRuleManager::hasRule(const std::string& name) const
{
    return rules.find(name) != rules.end();
}

const std::vector<PWRule>& PWRuleManager::getRules(const std::string& name) const
{
    return rules.find(name)->second;
}
