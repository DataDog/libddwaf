// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <chrono>
#include <ddwaf.h>
#include <iostream>
#include <stack>
#include <vector>

#include "run_fixture.hpp"
#include "utils.hpp"

namespace ddwaf::benchmark {

run_fixture::run_fixture(ddwaf_handle handle, ddwaf_object object)
    : object_(object), handle_(handle)
{}

bool run_fixture::set_up()
{
    ctx_ = ddwaf_context_init(handle_);
    return ctx_ != nullptr;
}

void run_fixture::warmup()
{
    std::stack<std::pair<const ddwaf_object *, std::size_t>> object_stack;
    object_stack.emplace(&object_, 0);
    while (!object_stack.empty()) {
        auto &[current, i] = object_stack.top();
        for (; i < current->nbEntries; ++i) {
            const auto &next = current->array[i];
            if (next.type == DDWAF_OBJ_ARRAY || next.type == DDWAF_OBJ_MAP) {
                break;
            }
        }
        if (i == current->nbEntries) {
            object_stack.pop();
        } else {
            object_stack.push({&current->array[i++], 0});
        }
    }
}

uint64_t run_fixture::test_main()
{
    ddwaf_result res;
    auto code = ddwaf_run(ctx_, &object_, nullptr, &res, std::numeric_limits<uint32_t>::max());
    if (code < 0) {
        throw std::runtime_error("WAF returned " + std::to_string(code));
    }

    if (res.timeout) {
        throw std::runtime_error("WAF timed-out");
    }

    uint64_t total_runtime = res.total_runtime;
    ddwaf_result_free(&res);

    return total_runtime;
}

void run_fixture::tear_down()
{
    if (ctx_ != nullptr) {
        ddwaf_context_destroy(ctx_);
    }
}

} // namespace ddwaf::benchmark
