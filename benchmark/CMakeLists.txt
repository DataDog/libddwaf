file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

add_executable(waf_benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_compile_options(waf_benchmark PRIVATE $<$<BOOL:${LIBDDWAF_ENABLE_LTO}>:-flto>)
target_link_libraries(waf_benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(waf_benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

add_custom_command(TARGET waf_benchmark POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:waf_benchmark> ${CMAKE_BINARY_DIR}/benchmark/benchmark
)
set_target_properties(waf_benchmark PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

add_custom_target(run_benchmark
    COMMAND $<TARGET_FILE:waf_benchmark>
    --scenarios=${CMAKE_CURRENT_SOURCE_DIR}/scenarios
    --iterations=1000
    --format=json
    --output=benchmark_results.json
    --fixtures="random"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_dependencies(run_benchmark waf_benchmark)

