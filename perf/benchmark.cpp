// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <iostream>
#include <ctime>
#include "random.hpp"

#include <ddwaf.h>
#include "runner.hpp"
#include "object_generator.hpp"
#include "rule_parser.hpp"
#include "run_fixture.hpp"

using namespace ddwaf;

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <json/yaml file> [<seed> <iterations>]\n";
        return EXIT_FAILURE;
    }

    unsigned seed = 0;
    if (argc >= 3) {
        seed = atoi(argv[2]);
    } else {
        std::random_device r;
        seed = r();
    }
    std::cout << "Seed: " << seed << std::endl;
    benchmark::random::seed(seed);

    size_t runs = 123;
    if (argc >= 4) {
        runs = atoi(argv[3]);
    }

    benchmark::runner runner;

    runner.register_fixture<benchmark::run_fixture>(
        "small objects", runs,
        std::string{argv[1]},
        benchmark::object_generator::limits{{0, 1}, {0, 20}, {0, 20}, 10});

    runner.run();

    return 0;
}
