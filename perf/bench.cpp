#include "common/utils.hpp"
#include <benchmark/benchmark.h>
#include <vector>
#include <yaml-cpp/node/parse.h>
#include "ddwaf_object.h"
#include "iterator.hpp"


ddwaf_object global;
static void BM_DDWAF_Iterator(benchmark::State& state) {
    for (auto _ : state) {
        ddwaf::value_iterator it{ddwaf::object_view{reinterpret_cast<ddwaf::detail::object*>(&global)}, {}, {}};
        for (; it ; ++it) {
            benchmark::DoNotOptimize(it.type());
        }
    }
}

// Load the YAML file and convert to ddwaf_object once before the benchmarks
struct Init {
    Init() {
        auto file_content = read_file("example.yaml");
        global = YAML::Load(file_content).as<ddwaf_object>();
    }

    ~Init() {
        ddwaf_object_destroy(&global, nullptr);
    }
};

// Initialize global_ddwaf_obj before the benchmark runs
Init init;

// Register the benchmark
BENCHMARK(BM_DDWAF_Iterator)->Arg(1);

// Generate the main function for the benchmark
BENCHMARK_MAIN();

