// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <iostream>

#include "run_fixture.hpp"
#include "object_generator.hpp"
#include "rule_parser.hpp"
#include "utils.hpp"

namespace ddwaf::benchmark
{

run_fixture::run_fixture(std::string_view filename,
  const object_generator::limits &limits)
{
    ddwaf_object rule = rule_parser::from_file(filename);

    ddwaf_config config {
        { limits.container_size.max,
          limits.container_depth.max,
          limits.string_length.max },
        { nullptr, nullptr } };

    handle_ = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);

    uint32_t addrs_len;
    auto addrs = ddwaf_required_addresses(handle_, &addrs_len);

    std::vector<std::string_view> addresses{
        addrs, addrs + static_cast<size_t>(addrs_len)};

    generator_ = object_generator(limits, std::move(addresses));
}

run_fixture::~run_fixture()
{
    if (handle_ != nullptr) {
        ddwaf_destroy(handle_);
    }
}

bool run_fixture::set_up()
{
    ctx_ = ddwaf_context_init(handle_, ddwaf_object_free);
    return ctx_ != nullptr;
}

uint64_t run_fixture::test_main() const
{
    ddwaf_object data = generator_();

    //std::cout << utils::object_to_string(data) << std::endl;

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
