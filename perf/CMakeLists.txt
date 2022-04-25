file(GLOB_RECURSE LIBDDWAF_BENCHMARK_SOURCE *.cpp)

add_executable(benchmark ${LIBDDWAF_BENCHMARK_SOURCE})
target_link_libraries(benchmark PRIVATE libddwaf_objects lib_yamlcpp lib_rapidjson m)
target_include_directories(benchmark PRIVATE ${libddwaf_SOURCE_DIR}/src)

