// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <iostream>
#include <ddwaf.h>

#include "run_fixture.hpp"
#include "object_generator.hpp"
#include "random.hpp"
#include "utils.hpp"

namespace ddwaf::benchmark
{

run_fixture::run_fixture(unsigned iterations, ddwaf_handle handle,
    const object_generator::limits &limits):
  handle_(handle)
{
    uint32_t addrs_len;
    auto addrs = ddwaf_required_addresses(handle_, &addrs_len);

    std::vector<std::string_view> addresses{
        addrs, addrs + static_cast<size_t>(addrs_len)};

    object_generator generator(limits, std::move(addresses));

    num_objects_ = std::min<std::size_t>(iterations, max_objects);
    for (std::size_t i = 0; i < num_objects_; i++) {
        objects_[i] = generator();
    }
}

run_fixture::~run_fixture()
{
    for (std::size_t i = 0; i < num_objects_; i++) {
        ddwaf_object_free(&objects_[i]);
    }
}

bool run_fixture::set_up()
{
    ctx_ = ddwaf_context_init(handle_, nullptr);
    return ctx_ != nullptr;
}

uint64_t run_fixture::test_main()
{
    ddwaf_object &data = objects_[random::get() % num_objects_];

    ddwaf_result res;
    auto code = ddwaf_run(ctx_, &data, &res, std::numeric_limits<uint32_t>::max());
    if (code < 0) {
        throw std::runtime_error("WAF returned " + std::to_string(code));
    }
    if (res.timeout) {
        throw std::runtime_error("WAF timed-out");
    }

    return res.total_runtime;
}

void run_fixture::tear_down()
{
    if (ctx_ != nullptr) {
        ddwaf_context_destroy(ctx_);
    }
}

}
