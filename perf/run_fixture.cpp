// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <ddwaf.h>
#include <iostream>
#include <vector>

#include "random.hpp"
#include "run_fixture.hpp"
#include "utils.hpp"

namespace ddwaf::benchmark {

run_fixture::run_fixture(ddwaf_handle handle, std::vector<ddwaf_object> &&objects)
    : objects_(std::move(objects)), handle_(handle)
{}

run_fixture::~run_fixture()
{
    for (auto &o : objects_) { ddwaf_object_free(&o); }
}

bool run_fixture::set_up()
{
    ctx_ = ddwaf_context_init(handle_);
    return ctx_ != nullptr;
}

uint64_t run_fixture::test_main()
{
    ddwaf_object &data = objects_[random::get() % objects_.size()];

    ddwaf_result res;
    auto code = ddwaf_run(ctx_, &data, nullptr, &res, std::numeric_limits<uint32_t>::max());
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
