// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <ddwaf.h>
#include <iostream>
#include <vector>

#include "context_destroy_fixture.hpp"
#include "random.hpp"
#include "utils.hpp"

namespace ddwaf::benchmark {

context_destroy_fixture::context_destroy_fixture(
    ddwaf_handle handle, std::vector<ddwaf_object> &&objects)
    : objects_(std::move(objects)), handle_(handle)
{}

context_destroy_fixture::~context_destroy_fixture()
{
    for (auto &o : objects_) { ddwaf_object_free(&o); }
}

bool context_destroy_fixture::set_up()
{
    ctx_ = ddwaf_context_init(handle_);

    ddwaf_object &data = objects_[random::get() % objects_.size()];
    ddwaf_run(ctx_, &data, nullptr, nullptr, std::numeric_limits<uint32_t>::max());

    return ctx_ != nullptr;
}

uint64_t context_destroy_fixture::test_main()
{
    auto start = std::chrono::system_clock::now();

    ddwaf_context_destroy(ctx_);

    return (std::chrono::system_clock::now() - start).count();
}

} // namespace ddwaf::benchmark
