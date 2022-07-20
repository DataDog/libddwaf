// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>

#include <context.hpp>
#include <PWRet.hpp>
#include <tuple>
#include <utils.h>

namespace ddwaf
{

context::context(ddwaf::manifest &manifest, ddwaf::flow_map &flows,
  const ddwaf::obfuscator &obfuscator, const ddwaf::object_limits &limits,
  ddwaf_object_free_fn free_fn):
    manifest_(manifest),
    flows_(flows),
    event_obfuscator_(obfuscator),
    limits_(limits),
    store_(manifest_, free_fn),
    processor_(store_, manifest_)
{
}

DDWAF_RET_CODE context::run(ddwaf_object newParameters,
                               optional_ref<ddwaf_result> res, uint64_t timeLeft)
{
    if (!store_.insert(newParameters)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return DDWAF_ERR_INVALID_OBJECT;
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
    if (!processor_.isFirstRun() && !store_.has_new_targets())
    {
        return DDWAF_GOOD;
    }

    PWRetManager retManager(event_obfuscator_);
    for (const auto& [key, flow] : flows_)
    {
        if (!processor_.runFlow(key, flow, retManager, deadline))
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

}
