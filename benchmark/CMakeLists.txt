file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

add_executable(benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_compile_options(benchmark PRIVATE $<$<BOOL:${LIBDDWAF_ENABLE_LTO}>:-flto>)
target_link_libraries(benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

set_target_properties(benchmark PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

add_custom_target(run_benchmark
    COMMAND ${CMAKE_BINARY_DIR}/perf/benchmark
    --scenarios=${CMAKE_CURRENT_SOURCE_DIR}/scenarios
    --iterations=1000
    --format=json
    --seed=1729
    --output=benchmark_results.json
    --raw
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_dependencies(run_benchmark benchmark)
