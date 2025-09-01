// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <ddwaf.h>
#include <iostream>
#include <stack>
#include <vector>

#include "run_fixture.hpp"
#include "utils.hpp"

namespace ddwaf::benchmark {

run_fixture::run_fixture(ddwaf_handle handle, std::vector<ddwaf_object> &&objects)
    : objects_(std::move(objects)), handle_(handle)
{}

bool run_fixture::set_up()
{
    ctx_ = ddwaf_context_init(handle_, ddwaf_get_default_allocator());
    return ctx_ != nullptr;
}

void run_fixture::warmup()
{
    static constexpr std::size_t max_depth = 3;
    for (auto &object : objects_) {
        std::stack<std::pair<const ddwaf_object *, std::size_t>> object_stack;
        object_stack.emplace(&object, 0);
        while (!object_stack.empty()) {
            auto &[current, i] = object_stack.top();
            for (; i < ddwaf_object_get_size(current); ++i) {
                const auto &next = *ddwaf_object_at_value(current, i);
                if (object_stack.size() <= max_depth &&
                    (next.type == DDWAF_OBJ_ARRAY || next.type == DDWAF_OBJ_MAP)) {
                    break;
                }
            }
            if (i == ddwaf_object_get_size(current)) {
                object_stack.pop();
            } else {
                object_stack.emplace(ddwaf_object_at_value(current, i++), 0);
            }
        }
    }
}

uint64_t run_fixture::test_main()
{
    uint64_t total_runtime = 0;

    for (auto &object : objects_) {
        ddwaf_object res{};

        auto *subctx = ddwaf_subcontext_init(ctx_);
        auto code = ddwaf_subcontext_eval(
            subctx, &object, false, &res, std::numeric_limits<uint32_t>::max());
        ddwaf_subcontext_destroy(subctx);
        if (code < 0) {
            throw std::runtime_error("WAF returned " + std::to_string(code));
        }

        const auto *timeout = ddwaf_object_find(&res, "timeout", sizeof("timeout") - 1);
        if (ddwaf_object_get_bool(timeout)) {
            throw std::runtime_error("WAF timed-out");
        }

        const auto *duration = ddwaf_object_find(&res, "duration", sizeof("duration") - 1);
        total_runtime += ddwaf_object_get_unsigned(duration);
        ddwaf_object_destroy(&res, ddwaf_get_default_allocator());
    }

    return total_runtime;
}

void run_fixture::tear_down()
{
    if (ctx_ != nullptr) {
        ddwaf_context_destroy(ctx_);
    }
}

} // namespace ddwaf::benchmark
