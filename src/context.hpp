// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include <processor.hpp>
#include <waf.hpp>
#include <ddwaf.h>
#include <limits.hpp>
#include <optional>
#include <utils.h>
#include <obfuscator.hpp>

namespace ddwaf
{

class context
{
public:
    context(ddwaf::manifest &manifest, ddwaf::flow_map &flows,
        const ddwaf::obfuscator &obfuscator, const ddwaf::object_limits &limits,
        ddwaf_object_free_fn free_fn);

    context(const context&) = delete;
    context& operator=(const context&) = delete;
    context(context&&) = default;
    context& operator=(context&&) = default;
    ~context() = default;

    DDWAF_RET_CODE run(ddwaf_object, optional_ref<ddwaf_result> res, uint64_t);

protected:
    ddwaf::manifest &manifest_;
    ddwaf::flow_map &flows_;

    const ddwaf::obfuscator &event_obfuscator_;
    const ddwaf::object_limits &limits_;

    ddwaf::object_store store_;
    ddwaf::processor processor_;
};

}
