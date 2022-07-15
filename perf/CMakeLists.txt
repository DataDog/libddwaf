file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

list(REMOVE_ITEM LIBDDWAF_BENCHMARK_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/benchcmp.cpp)

add_executable(benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_link_libraries(benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

add_executable(benchcmp benchcmp.cpp)
target_link_libraries(benchcmp PRIVATE lib_yamlcpp m)

add_executable(benchmerge benchmerge.cpp)
target_link_libraries(benchmerge PRIVATE lib_yamlcpp m)

ExternalProject_Get_property(proj_event_rules SOURCE_DIR)
set(EVENT_RULES_SOURCE_DIR ${SOURCE_DIR})

add_custom_target(run_benchmark
    COMMAND ${CMAKE_BINARY_DIR}/perf/benchmark
    --rule-repo=${EVENT_RULES_SOURCE_DIR}
    --iterations=1000
    --format=json
    --seed=1729
    --output=benchmark_results.json
    --raw
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_dependencies(run_benchmark benchmark proj_event_rules)
