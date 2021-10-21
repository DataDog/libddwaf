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
      retriever(wafHandle->manifest, wafHandle->maxMapDepth, wafHandle->maxArrayLength),
      processor(retriever, wafHandle->rules),
      obj_free(ddwaf_object_free)
{
    argCache.reserve(ADDITIVE_BUFFER_PREALLOC);
}

PWAdditive::PWAdditive(const ddwaf_handle _waf, ddwaf_object_free_fn free_fn)
    : wafHandle((const PowerWAF*) _waf),
      retriever(wafHandle->manifest, wafHandle->maxMapDepth, wafHandle->maxArrayLength),
      processor(retriever, wafHandle->rules),
      obj_free(free_fn)
{
    argCache.reserve(ADDITIVE_BUFFER_PREALLOC);
}

ddwaf_result PWAdditive::run(ddwaf_object newParameters, uint64_t timeLeft)
{
    if (!retriever.addParameter(newParameters))
    {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        if (obj_free != nullptr)
        {
            obj_free(&newParameters);
        }
        return returnErrorCode(DDWAF_ERR_INVALID_OBJECT);
    }

    // Take ownership of newParameters
    argCache.emplace_back(newParameters);

    // If the timeout provided is 0, we need to ensure the parameters are owned
    // by the additive to ensure that the semantics of DDWAF_ERR_TIMEOUT are
    // consistent across all possible timeout scenarios.
    if (timeLeft == 0)
    {
        return returnErrorCode(DDWAF_ERR_TIMEOUT);
    }

    const SQPowerWAF::monotonic_clock::time_point now      = SQPowerWAF::monotonic_clock::now();
    const SQPowerWAF::monotonic_clock::time_point deadline = now + std::chrono::microseconds(timeLeft);

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!processor.isFirstRun() && !retriever.hasNewArgs())
    {
        return returnErrorCode(DDWAF_GOOD);
    }

    processor.startNewRun(deadline);

    PWRetManager retManager(wafHandle->maxTimeStore, processor.getGlobalAllocator());
    for (const auto& [key, flow] : wafHandle->flows)
    {
        processor.runFlow(key, flow, retManager);
    }

    ddwaf_result output = retManager.synthetize();

    const SQPowerWAF::monotonic_clock::duration runTime = SQPowerWAF::monotonic_clock::now() - now;
    output.perfTotalRuntime                             = (uint32_t) std::min(runTime.count() / 1000, SQPowerWAF::monotonic_clock::duration::rep(UINT32_MAX));

    return output;
}

void PWAdditive::flushCaches()
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
