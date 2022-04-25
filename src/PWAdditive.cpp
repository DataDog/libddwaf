// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>

#include <PWAdditive.hpp>
#include <PWRet.hpp>
#include <tuple>
#include <utils.h>

PWAdditive::PWAdditive(std::shared_ptr<PowerWAF> _wafReference)
    : wafReference(_wafReference),
      wafHandle(_wafReference.get()),
      object_validator(wafHandle->limits),
      event_obfuscator(wafHandle->event_obfuscator),
      retriever(wafHandle->manifest, wafHandle->limits),
      processor(retriever, wafHandle->rules),
      obj_free(ddwaf_object_free)
{
    argCache.reserve(ADDITIVE_BUFFER_PREALLOC);
}

PWAdditive::PWAdditive(const ddwaf_handle _waf, ddwaf_object_free_fn free_fn)
    : wafHandle((const PowerWAF*) _waf),
      object_validator(wafHandle->limits),
      event_obfuscator(wafHandle->event_obfuscator),
      retriever(wafHandle->manifest, wafHandle->limits),
      processor(retriever, wafHandle->rules),
      obj_free(free_fn)
{
    if (obj_free != nullptr)
    {
        argCache.reserve(ADDITIVE_BUFFER_PREALLOC);
    }
}

PWAdditive::~PWAdditive()
{
    if (obj_free == nullptr)
    {
        return;
    }

    for (ddwaf_object& arg : argCache)
    {
        obj_free(&arg);
    }
}

DDWAF_RET_CODE PWAdditive::run(ddwaf_object newParameters,
                               optional_ref<ddwaf_result> res, uint64_t timeLeft)
{
    if (!object_validator.validate(newParameters))
    {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        if (obj_free != nullptr)
        {
            obj_free(&newParameters);
        }
        return DDWAF_ERR_INVALID_OBJECT;
    }

    retriever.addParameter(newParameters);
    if (obj_free != nullptr)
    {
        // Take ownership of newParameters
        argCache.emplace_back(newParameters);
    }

    // If the timeout provided is 0, we need to ensure the parameters are owned
    // by the additive to ensure that the semantics of DDWAF_ERR_TIMEOUT are
    // consistent across all possible timeout scenarios.
    if (timeLeft == 0)
    {
        if (res.has_value())
        {
            ddwaf_result& output = *res;
            output.timeout       = true;
        }
        return DDWAF_GOOD;
    }

    const auto start    = ddwaf::monotonic_clock::now();
    const auto deadline = start + std::chrono::microseconds(timeLeft);

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!processor.isFirstRun() && !retriever.hasNewArgs())
    {
        return DDWAF_GOOD;
    }

    processor.startNewRun(deadline);

    PWRetManager retManager(event_obfuscator);
    for (const auto& [key, flow] : wafHandle->flows)
    {
        if (!processor.runFlow(key, flow, retManager))
        {
            break;
        }
    }

    DDWAF_RET_CODE code = retManager.getResult();
    if (res.has_value())
    {
        ddwaf_result& output = *res;
        retManager.synthetize(output);
        output.total_runtime = (ddwaf::monotonic_clock::now() - start).count();
    }

    return code;
}
