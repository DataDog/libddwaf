// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <unordered_map>

#include "Clock.hpp"
#include <PWProcessor.hpp>
#include <PWRet.hpp>
#include <PWRetriever.hpp>
#include <PowerWAF.hpp>
#include <ddwaf.h>
#include <exception.hpp>
#include <iostream>
#include <log.hpp>
#include <parameter.hpp>
#include <stdexcept>
#include <utils.h>
#include <parser/parser.hpp>

using namespace ddwaf;
using namespace std::literals;

PowerWAF::PowerWAF(PWManifest&& manifest_, PWRuleManager&& ruleManager_,
                   std::unordered_map<std::string, std::vector<std::string>>&& flows_,
                   const ddwaf_config* config)
    : manifest(std::move(manifest_)),
      ruleManager(std::move(ruleManager_)),
      flows(std::move(flows_))
{
    if (config != nullptr)
    {
        if (config->maxArrayLength != 0)
        {
            maxArrayLength = config->maxArrayLength;
        }

        if (config->maxMapDepth != 0)
        {
            maxMapDepth = config->maxMapDepth;
        }

        if (config->maxTimeStore >= 0)
        {
            maxTimeStore = config->maxTimeStore;
        }
    }
}

PowerWAF* PowerWAF::fromConfig(const ddwaf_object rules_, const ddwaf_config* config)
{
    PWRuleManager ruleManager;
    PWManifest manifest;
    std::unordered_map<std::string, std::vector<std::string>> flows;

    try
    {
        auto ruleset = parameter(rules_);
        parser::parse(ruleset, ruleManager, manifest, flows);
        return new PowerWAF(std::move(manifest), std::move(ruleManager),
                            std::move(flows), config);
    }
    catch (const std::exception& e)
    {
        DDWAF_ERROR("%s", e.what());
    }

    return nullptr;
}
