// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "common/utils.hpp"
#include "ddwaf.h"
#include "generator/extract_schema.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <type_traits>
#include <unordered_set>
#include <variant>


int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [file ...]\n";
        return EXIT_FAILURE;
    }

    std::string raw_payload = read_file(argv[1]);
    auto payload = YAML::Load(raw_payload).as<ddwaf_object>();

    ddwaf::generator::extract_schema generator;
    auto start = std::chrono::system_clock::now();
    auto schema = generator.generate(&payload);

    std::cout << (std::chrono::system_clock::now() - start).count() << std::endl;

    ddwaf_object_free(&payload);
    ddwaf_object_free(&schema);


    return EXIT_SUCCESS;
}
