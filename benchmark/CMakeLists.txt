file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

add_executable(benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_compile_options(benchmark PRIVATE $<$<BOOL:${LIBDDWAF_ENABLE_LTO}>:-flto>)
target_link_libraries(benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

set_target_properties(benchmark PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

add_custom_target(run_benchmark_json
    COMMAND $<TARGET_FILE:benchmark>
    --scenarios=${CMAKE_CURRENT_SOURCE_DIR}/scenarios
    --iterations=1
    --format=json
    --output=benchmark_results.json
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_dependencies(run_benchmark_json benchmark)

add_custom_target(run_benchmark_human
    COMMAND $<TARGET_FILE:benchmark>
    --scenarios=${CMAKE_CURRENT_SOURCE_DIR}/scenarios
    --runs 2
    --iterations=1000
    --format=human
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_dependencies(run_benchmark_human benchmark)
