// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PowerWAF.hpp>
#include <metrics.hpp>

namespace ddwaf
{

ddwaf_metrics metrics_collector::generate_metrics()
{
    ddwaf_metrics final_metrics = {total_runtime_, {0}};
    ddwaf_object_map(&final_metrics.rule_runtime);

    for (unsigned i = 0; i < rule_runtime_.size(); i++) {
        if (rule_runtime_[i] == 0) { continue; }

        // TODO this is weird
        const std::string &rule_id = rules_.find(i)->second.id;
        ddwaf_object duration;
        ddwaf_object_unsigned_force(&duration, rule_runtime_[i]);
        ddwaf_object_map_addl(&final_metrics.rule_runtime, 
            rule_id.c_str(), rule_id.size(), &duration);
    }

    return final_metrics;
}

}

extern "C"
{

ddwaf_metrics_collector ddwaf_metrics_collector_init(const ddwaf_handle handle)
{
    if (handle == nullptr) {
        return nullptr;
    }

    PowerWAF *waf = reinterpret_cast<PowerWAF*>(handle);
    return reinterpret_cast<ddwaf_metrics_collector>(
        new ddwaf::metrics_collector(waf->rules));
}

void ddwaf_get_metrics(ddwaf_metrics_collector collector, ddwaf_metrics *metrics)
{
    if (collector == nullptr || metrics == nullptr) { return; }

    *metrics = reinterpret_cast<ddwaf::metrics_collector*>(collector)->generate_metrics();
}

void ddwaf_metrics_collector_destroy(ddwaf_metrics_collector collector)
{
    delete reinterpret_cast<ddwaf::metrics_collector*>(collector);
}

void ddwaf_metrics_free(ddwaf_metrics *metrics)
{
    if (metrics != nullptr)
    {
        ddwaf_object_free(&metrics->rule_runtime);
    }
}

}
