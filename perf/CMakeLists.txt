file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

list(REMOVE_ITEM LIBDDWAF_BENCHMARK_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/benchcmp.cpp)
list(REMOVE_ITEM LIBDDWAF_BENCHMARK_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/benchmerge.cpp)

add_executable(waf_benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_link_libraries(waf_benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(waf_benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

add_executable(benchcmp benchcmp.cpp)
target_link_libraries(benchcmp PRIVATE lib_yamlcpp m)

add_executable(benchmerge benchmerge.cpp)
target_link_libraries(benchmerge PRIVATE lib_yamlcpp m)

set_target_properties(waf_benchmark PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

set_target_properties(benchcmp PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

set_target_properties(benchmerge PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)


ExternalProject_Get_property(proj_event_rules SOURCE_DIR)
set(EVENT_RULES_SOURCE_DIR ${SOURCE_DIR})

add_custom_target(run_benchmark
    COMMAND ${CMAKE_BINARY_DIR}/perf/waf_benchmark
    --rule-repo=${EVENT_RULES_SOURCE_DIR}
    --iterations=1000
    --format=json
    --seed=1729
    --output=benchmark_results.json
    --raw
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_dependencies(run_benchmark waf_benchmark proj_event_rules)
