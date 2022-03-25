// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <unordered_map>

#include "clock.hpp"
#include <PWProcessor.hpp>
#include <PWRet.hpp>
#include <PWRetriever.hpp>
#include <PowerWAF.hpp>
#include <ddwaf.h>
#include <exception.hpp>
#include <iostream>
#include <log.hpp>
#include <parameter.hpp>
#include <parser/parser.hpp>
#include <stdexcept>
#include <utils.h>

using namespace ddwaf;
using namespace std::literals;

PowerWAF::PowerWAF(PWManifest&& manifest_, rule_vector&& rules_,
                   flow_map&& flows_, const ddwaf_config* config)
    : manifest(std::move(manifest_)),
      rules(std::move(rules_)),
      flows(std::move(flows_))
{
	re2::RE2::Options options;
	options.set_max_mem(512 * 1024);
	options.set_log_errors(false);
	options.set_case_sensitive(false);
	
	sensitiveRegex = std::make_shared<re2::RE2>("(p(ass)?w(or)?d|pass(_?phrase)?|secret|(api_?|private_?|public_?)key)|token|consumer_?(id|key|secret)|sign(ed|ature)|bearer", options);
	
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
    }
}

PowerWAF* PowerWAF::fromConfig(const ddwaf_object ruleset,
                               const ddwaf_config* config, ddwaf::ruleset_info& info)
{
    PWManifest manifest;
    rule_vector rules;
    flow_map flows;

    try
    {
        parser::parse(ruleset, info, rules, manifest, flows);
        return new PowerWAF(std::move(manifest), std::move(rules),
                            std::move(flows), config);
    }
    catch (const std::exception& e)
    {
        DDWAF_ERROR("%s", e.what());
    }

    return nullptr;
}
