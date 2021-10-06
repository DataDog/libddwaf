// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string>
#include <vector>
#include <unordered_map>
#include <PWRetriever.hpp>
#include <PWManifest.h>
#include <PWRuleManager.hpp>
#include <parameter.hpp>

namespace ddwaf::parser {

void parse(parameter& ruleset, PWRuleManager& ruleManager, PWManifest& manifest,
           std::unordered_map<std::string, std::vector<std::string>>& flows);

}
