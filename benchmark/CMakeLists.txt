set(LIBDDWAF_BENCHMARK_SOURCE 
    main.cpp
    utils.cpp
    output_formatter.cpp
    rule_parser.cpp
    run_fixture.cpp
    runner.cpp
    utils.cpp
    yaml_helpers.cpp)

add_executable(benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_compile_options(benchmark PRIVATE $<$<BOOL:${LIBDDWAF_ENABLE_LTO}>:-flto>)
target_link_libraries(benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

set_target_properties(benchmark PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

add_custom_target(run_benchmark
    COMMAND $<TARGET_FILE:benchmark>
    --scenarios=${CMAKE_CURRENT_SOURCE_DIR}/scenarios
    --iterations=1000
    --format=json
    --output=benchmark_results.json
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
add_dependencies(run_benchmark benchmark)

set(LIBDDWAF_OBJECT_GENERATOR_SOURCE 
    object_generator.cpp
    random.cpp
    utils.cpp
    yaml_helpers.cpp)

add_executable(object_generator ${LIBDDWAF_OBJECT_GENERATOR_SOURCE})
target_link_libraries(object_generator PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(object_generator PRIVATE ${libddwaf_SOURCE_DIR}/src)
